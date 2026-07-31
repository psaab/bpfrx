package dhcprelay

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"
)

// #6562 — outstanding-request binding for relayed replies, and the FORCERENEW
// refusal. Two DISTINCT defects, so two distinct fail-on-revert binders:
//
//   - TestHandleServerResponses_NoOutstandingRequestDropped — a reply that
//     answers no forwarded request is dropped (reverting the ir.pending.matches
//     gate makes it RED).
//   - TestHandleServerResponses_ForceRenewRefused (delivery_test.go) — an
//     unauthenticated FORCERENEW is not forwarded (restoring
//     messageTypeForceRenew to the forwarded set makes it RED).
//
// And one OVER-REACH guard that must stay GREEN under revert:
//
//   - TestRelay_NormalExchange_EndToEndStillRelays — DISCOVER/OFFER,
//     REQUEST/ACK, RENEW and REBIND still relay end-to-end through the live
//     manager. A binding that is too strict silently breaks DHCP for every real
//     client, which is a worse outage than the injection it prevents, so this
//     test is the one that must never be "fixed" by loosening an assertion.

// bindingHarness drives a full relay session (the REAL runRelay ->
// runRelaySession client loop plus the handleServerResponses reply loop, both
// sharing one interfaceRelay) so the pending-table entry is created by
// production code, not by a test helper.
type bindingHarness struct {
	t      *testing.T
	m      *Manager
	client *fakeConn
	server *fakeConn
	stop   func()
}

// relay returns the single interfaceRelay this harness is running, so a test
// can assert on the counters the production loops actually incremented.
func (h *bindingHarness) relay() *interfaceRelay {
	h.t.Helper()
	h.m.mu.Lock()
	defer h.m.mu.Unlock()
	for _, ir := range h.m.relays {
		return ir
	}
	h.t.Fatal("no relay is running")
	return nil
}

// newBindingHarness starts a relay on the single-interface config. The server
// conn reports 192.0.2.1 as its source so replies pass the #4163 source check
// (that is singleInterfaceConfig's configured server).
func newBindingHarness(t *testing.T) *bindingHarness {
	t.Helper()
	client := newFakeConn()
	server := newFakeConn()
	server.mu.Lock()
	server.srcAddr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: relayPort}
	server.mu.Unlock()

	factory, _ := recordingFactory(client, server)
	m := testManager(factory)
	m.Apply(context.Background(), singleInterfaceConfig())
	return &bindingHarness{t: t, m: m, client: client, server: server, stop: m.Stop}
}

// relayUp pushes a client BOOTREQUEST and returns the datagram the relay
// forwarded upstream. It fails the test if nothing is relayed in time.
func (h *bindingHarness) relayUp(req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	h.t.Helper()
	before := h.server.writeCount()
	h.client.push(req.ToBytes())
	if !waitFor(func() bool { return h.server.writeCount() > before }) {
		h.t.Fatalf("request (xid %v) was not relayed upstream within the deadline",
			req.TransactionID)
	}
	h.server.mu.Lock()
	data := append([]byte(nil), h.server.writes[len(h.server.writes)-1].data...)
	h.server.mu.Unlock()
	got, err := dhcpv4.FromBytes(data)
	if err != nil {
		h.t.Fatalf("relayed datagram does not parse: %v", err)
	}
	return got
}

// relayDown pushes a server reply and returns the datagram delivered to the
// client, or nil if none was delivered before the deadline.
func (h *bindingHarness) relayDown(reply *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	h.t.Helper()
	before := h.client.writeCount()
	h.server.push(reply.ToBytes())
	if !waitFor(func() bool { return h.client.writeCount() > before }) {
		return nil
	}
	h.client.mu.Lock()
	data := append([]byte(nil), h.client.writes[len(h.client.writes)-1].data...)
	h.client.mu.Unlock()
	got, err := dhcpv4.FromBytes(data)
	if err != nil {
		h.t.Fatalf("delivered datagram does not parse: %v", err)
	}
	return got
}

// waitFor polls cond until true or a 2s deadline elapses.
func waitFor(cond func() bool) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

// newRequest builds a client BOOTREQUEST of the given type.
func newRequest(t *testing.T, mt dhcpv4.MessageType, chaddr net.HardwareAddr,
	ciaddr net.IP) *dhcpv4.DHCPv4 {
	t.Helper()
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	pkt.OpCode = dhcpv4.OpcodeBootRequest
	pkt.HWType = iana.HWTypeEthernet
	pkt.ClientHWAddr = chaddr
	pkt.UpdateOption(dhcpv4.OptMessageType(mt))
	if ciaddr != nil {
		pkt.ClientIPAddr = ciaddr
	}
	return pkt
}

// serverReply builds the BOOTREPLY a conformant server would return for req:
// RFC 2131 §4.3.1 Table 3 copies 'xid' and 'chaddr' from the client's message,
// which is exactly the #6562 binding key. broadcast selects the delivery row
// (broadcast -> a client-conn UDP write, which is what the harness observes).
func serverReply(t *testing.T, req *dhcpv4.DHCPv4, mt dhcpv4.MessageType,
	yiaddr, ciaddr net.IP, broadcast bool) *dhcpv4.DHCPv4 {
	t.Helper()
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	pkt.OpCode = dhcpv4.OpcodeBootReply
	pkt.HWType = iana.HWTypeEthernet
	pkt.TransactionID = req.TransactionID // Table 3: 'xid' from client
	pkt.ClientHWAddr = req.ClientHWAddr   // Table 3: 'chaddr' from client
	pkt.UpdateOption(dhcpv4.OptMessageType(mt))
	pkt.YourIPAddr = net.IPv4zero
	pkt.ClientIPAddr = net.IPv4zero
	if yiaddr != nil {
		pkt.YourIPAddr = yiaddr
	}
	if ciaddr != nil {
		pkt.ClientIPAddr = ciaddr
	}
	if broadcast {
		pkt.SetBroadcast()
	}
	return pkt
}

// TestRelay_NormalExchange_EndToEndStillRelays is the #6562 OVER-REACH GUARD.
//
// It drives a complete, ordinary DHCP lifecycle through the live relay —
// DISCOVER/OFFER, REQUEST/ACK, then RENEW and REBIND — and asserts every
// message crosses the relay in both directions. Nothing here is armed by a test
// helper: each binding is created by the production client loop as it forwards
// the request upstream.
//
// This test MUST stay GREEN when the #6562 gate is reverted. If it ever goes
// red, the binding is dropping legitimate traffic and the fix is worse than the
// defect — an unbindable reply is a silent, segment-wide DHCP outage, whereas
// the injection it prevents needs an attacker to both spoof a configured
// server's source IP and guess a 32-bit xid.
func TestRelay_NormalExchange_EndToEndStillRelays(t *testing.T) {
	h := newBindingHarness(t)
	defer h.stop()

	chaddr := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x42}
	yiaddr := net.IPv4(10, 0, 0, 77)

	// --- DISCOVER -> OFFER -------------------------------------------------
	discover := newRequest(t, dhcpv4.MessageTypeDiscover, chaddr, nil)
	relayed := h.relayUp(discover)
	if relayed.TransactionID != discover.TransactionID {
		t.Fatalf("relayed DISCOVER xid = %v, want %v",
			relayed.TransactionID, discover.TransactionID)
	}
	offer := h.relayDown(serverReply(t, discover, dhcpv4.MessageTypeOffer, yiaddr, nil, true))
	if offer == nil {
		t.Fatal("OFFER answering a relayed DISCOVER was NOT delivered to the client " +
			"— the #6562 binding is over-strict and has broken normal DHCP")
	}
	if offer.TransactionID != discover.TransactionID {
		t.Errorf("delivered OFFER xid = %v, want %v", offer.TransactionID, discover.TransactionID)
	}

	// --- REQUEST -> ACK ----------------------------------------------------
	// RFC 2131 §4.4.1: "The DHCPREQUEST message contains the same 'xid' as the
	// DHCPOFFER message", so the SELECTING request reuses the DISCOVER xid.
	// This also exercises the no-consume-on-match rule: the DISCOVER's entry
	// was already matched by the OFFER above.
	request := newRequest(t, dhcpv4.MessageTypeRequest, chaddr, nil)
	request.TransactionID = discover.TransactionID
	h.relayUp(request)
	ack := h.relayDown(serverReply(t, request, dhcpv4.MessageTypeAck, yiaddr, nil, true))
	if ack == nil {
		t.Fatal("ACK answering a relayed REQUEST was NOT delivered to the client")
	}

	// --- RENEW (unicast REQUEST with ciaddr, fresh xid) --------------------
	// A renewing client sets ciaddr and picks a new transaction. The reply is
	// flag-clear with a real ciaddr, so it takes the ciaddr-unicast row.
	renew := newRequest(t, dhcpv4.MessageTypeRequest, chaddr, yiaddr)
	if renew.TransactionID == discover.TransactionID {
		t.Fatal("RENEW must use a fresh xid for this test to be meaningful")
	}
	h.relayUp(renew)
	renewAck := h.relayDown(serverReply(t, renew, dhcpv4.MessageTypeAck, nil, yiaddr, false))
	if renewAck == nil {
		t.Fatal("ACK answering a relayed RENEW was NOT delivered to the client")
	}

	// --- REBIND (broadcast REQUEST with ciaddr, fresh xid) -----------------
	rebind := newRequest(t, dhcpv4.MessageTypeRequest, chaddr, yiaddr)
	rebind.SetBroadcast()
	h.relayUp(rebind)
	rebindAck := h.relayDown(serverReply(t, rebind, dhcpv4.MessageTypeAck, nil, yiaddr, true))
	if rebindAck == nil {
		t.Fatal("ACK answering a relayed REBIND was NOT delivered to the client")
	}

	// No drop counter may have moved during an entirely legitimate exchange.
	ir := h.relay()
	if got := ir.repliesDroppedNoRequest.Load(); got != 0 {
		t.Errorf("repliesDroppedNoRequest = %d, want 0 — a NORMAL exchange must not "+
			"trip the binding", got)
	}
	if got := ir.pending.evictions(); got != 0 {
		t.Errorf("pendingEvicted = %d, want 0 (4 requests cannot fill an %d-entry table)",
			got, ir.pending.capacity())
	}
	if got := ir.repliesForwarded.Load(); got != 4 {
		t.Errorf("repliesForwarded = %d, want 4 (OFFER, ACK, RENEW-ACK, REBIND-ACK)", got)
	}
}

// TestHandleServerResponses_NoOutstandingRequestDropped is the #6562
// fail-on-revert gate for the FIRST defect: a syntactically valid OFFER from a
// CONFIGURED server (so #4163 passes) that answers NO request the relay
// forwarded MUST be dropped before it reaches the client, and
// repliesDroppedNoRequest MUST increment.
//
// This is the spoofed-source injection #4163 cannot stop: the attacker forges
// the configured server's IP, so the only thing left to catch them is that they
// did not guess an outstanding transaction. Reverting the ir.pending.matches
// gate makes this RED — the forged OFFER is forwarded and the counter stays 0.
func TestHandleServerResponses_NoOutstandingRequestDropped(t *testing.T) {
	offer := newReply(t, true, testYiaddr, nil, testChaddr) // broadcast → client write
	offer.GatewayIPAddr = testGiaddr
	serverConn := newFakeConn()
	serverConn.mu.Lock()
	serverConn.pending = [][]byte{offer.ToBytes()}
	serverConn.mu.Unlock()
	clientConn := newFakeConn()
	defer clientConn.Close()
	fl2 := &fakeL2{}
	// Live but EMPTY table: no request was ever relayed for this xid.
	ir := unarmedRelay("ge-0-0-0")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		// Source IS a configured server, so the #4163 check admits it and the
		// ONLY thing that can drop it is the #6562 binding.
		handleServerResponses(ctx, serverConn, clientConn, ir, fl2, testGiaddr, testServerSet())
		close(done)
	}()

	if !waitFor(func() bool { return ir.repliesDroppedNoRequest.Load() > 0 }) {
		t.Error("unbound reply was not dropped within the deadline")
	}

	if got := ir.repliesDroppedNoRequest.Load(); got != 1 {
		t.Errorf("repliesDroppedNoRequest = %d, want 1", got)
	}
	clientConn.mu.Lock()
	nWrites := len(clientConn.writes)
	clientConn.mu.Unlock()
	if nWrites != 0 {
		t.Errorf("unbound reply reached the client: got %d client writes, want 0", nWrites)
	}
	if ir.repliesForwarded.Load() != 0 {
		t.Errorf("repliesForwarded = %d, want 0", ir.repliesForwarded.Load())
	}
	if fl2.callCount() != 0 {
		t.Errorf("unbound reply used raw-L2: got %d calls, want 0", fl2.callCount())
	}
	// The source WAS configured, so this must not be miscounted as a #4163 drop
	// — the two counters have to stay independently diagnosable.
	if got := ir.repliesDroppedUnknownServer.Load(); got != 0 {
		t.Errorf("repliesDroppedUnknownServer = %d, want 0 (source was configured)", got)
	}

	cancel()
	serverConn.Close()
	<-done
}

// TestHandleServerResponses_WrongChaddrDropped proves the binding is keyed on
// client identity too, not on the xid alone: an attacker who observed or
// guessed an outstanding xid still cannot steer a DIFFERENT client, because the
// chaddr the server must echo (RFC 2131 §4.3.1 Table 3) will not match.
func TestHandleServerResponses_WrongChaddrDropped(t *testing.T) {
	victim := newReply(t, true, testYiaddr, nil, testChaddr)
	// Same xid, different client hardware address.
	forged := newReply(t, true, testYiaddr, nil,
		net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xAA})
	forged.TransactionID = victim.TransactionID

	serverConn := newFakeConn()
	serverConn.mu.Lock()
	serverConn.pending = [][]byte{forged.ToBytes()}
	serverConn.mu.Unlock()
	clientConn := newFakeConn()
	defer clientConn.Close()
	fl2 := &fakeL2{}
	ir := armedRelay("ge-0-0-0", victim) // armed for the VICTIM's chaddr only

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		handleServerResponses(ctx, serverConn, clientConn, ir, fl2, testGiaddr, testServerSet())
		close(done)
	}()

	if !waitFor(func() bool { return ir.repliesDroppedNoRequest.Load() > 0 }) {
		t.Error("reply with a mismatched chaddr was not dropped within the deadline")
	}
	clientConn.mu.Lock()
	nWrites := len(clientConn.writes)
	clientConn.mu.Unlock()
	if nWrites != 0 {
		t.Errorf("xid-only match forwarded a reply for the wrong client: got %d writes, want 0",
			nWrites)
	}

	cancel()
	serverConn.Close()
	<-done
}

// TestPendingTable_MatchDoesNotConsume pins the multi-reply rule: the relay
// fans each request out to EVERY server in the group, so an N-server group
// answers one DISCOVER with N OFFERs, and the SELECTING ACK reuses the same
// xid. Consuming the entry on first match would drop every reply after the
// first and silently break multi-server redundancy.
func TestPendingTable_MatchDoesNotConsume(t *testing.T) {
	tbl := newPendingTable(defaultTestPendingCap(), pendingTTL, time.Now)
	k := pendingKey{xid: dhcpv4.TransactionID{1, 2, 3, 4}, hlen: 6}
	tbl.insert(k)

	for i := 1; i <= 5; i++ {
		if !tbl.matches(k) {
			t.Fatalf("match %d failed: the entry was consumed by an earlier match", i)
		}
	}
}

// TestPendingTable_Expiry proves entries stop binding after the TTL, so the
// window in which a guessed xid would be accepted is bounded.
func TestPendingTable_Expiry(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	tbl := newPendingTable(defaultTestPendingCap(), 30*time.Second, clock)
	k := pendingKey{xid: dhcpv4.TransactionID{9, 9, 9, 9}, hlen: 6}
	tbl.insert(k)

	if !tbl.matches(k) {
		t.Fatal("entry does not match immediately after insert")
	}
	now = now.Add(29 * time.Second)
	if !tbl.matches(k) {
		t.Error("entry expired early (29s into a 30s TTL) — this would drop legitimate replies")
	}
	now = now.Add(2 * time.Second) // 31s: past the TTL
	if tbl.matches(k) {
		t.Error("entry still matches after the TTL — the binding window is unbounded")
	}
}

// TestPendingTable_CapEvictsOldestNotNewest pins the eviction policy. At the
// cap the table evicts the OLDEST entry rather than refusing the NEW request:
// refusing new requests would let an attacker who fills the table lock out
// every new client (a total segment outage), whereas evicting the oldest keeps
// new clients working. The eviction must also be COUNTED, because it is the
// only warning an operator gets that legitimate bindings are being lost.
func TestPendingTable_CapEvictsOldestNotNewest(t *testing.T) {
	now := time.Unix(2000, 0)
	clock := func() time.Time { return now }
	const capacity = 4
	tbl := newPendingTable(capacity, time.Hour, clock) // long TTL: force CAP pressure, not expiry

	key := func(n byte) pendingKey {
		return pendingKey{xid: dhcpv4.TransactionID{0, 0, 0, n}, hlen: 6}
	}
	// Fill to capacity, each entry one second newer than the last.
	for i := byte(1); i <= capacity; i++ {
		tbl.insert(key(i))
		now = now.Add(time.Second)
	}
	if tbl.occupancy() != capacity {
		t.Fatalf("occupancy = %d, want %d after filling to capacity", tbl.occupancy(), capacity)
	}
	if got := tbl.evictions(); got != 0 {
		t.Fatalf("evictions = %d, want 0 before the cap is exceeded", got)
	}

	// One more: the NEW entry must be admitted and the OLDEST dropped.
	tbl.insert(key(99))

	if !tbl.matches(key(99)) {
		t.Error("the NEW request was refused at the cap — an attacker filling the table " +
			"would lock out every new client")
	}
	if tbl.matches(key(1)) {
		t.Error("the OLDEST entry survived; eviction did not pick it")
	}
	if tbl.occupancy() != capacity {
		t.Errorf("occupancy = %d, want %d (the table must stay bounded)", tbl.occupancy(), capacity)
	}
	if got := tbl.evictions(); got != 1 {
		t.Errorf("evictions = %d, want 1 — cap pressure MUST be observable", got)
	}
	// The other pre-existing entries must be untouched: eviction is one-at-a-
	// time, not a table flush.
	for i := byte(2); i <= capacity; i++ {
		if !tbl.matches(key(i)) {
			t.Errorf("entry %d was evicted; only the single oldest should have been", i)
		}
	}
}

// TestPendingTable_ExpiredReclaimedBeforeEviction proves an expired entry is
// reclaimed as free space rather than counted as an eviction — an idle-then-
// busy relay must not report cap pressure it is not under.
func TestPendingTable_ExpiredReclaimedBeforeEviction(t *testing.T) {
	now := time.Unix(3000, 0)
	clock := func() time.Time { return now }
	const capacity = 3
	tbl := newPendingTable(capacity, 10*time.Second, clock)

	key := func(n byte) pendingKey {
		return pendingKey{xid: dhcpv4.TransactionID{0, 0, 0, n}, hlen: 6}
	}
	for i := byte(1); i <= capacity; i++ {
		tbl.insert(key(i))
	}
	now = now.Add(11 * time.Second) // every entry is now expired

	tbl.insert(key(50))
	if got := tbl.evictions(); got != 0 {
		t.Errorf("evictions = %d, want 0 — expired entries are free space, not cap pressure", got)
	}
	if !tbl.matches(key(50)) {
		t.Error("new entry not admitted after expired entries were reclaimed")
	}
}

// TestPendingTable_NilFailsClosed pins the fail-closed posture: a mis-wired
// (nil) table admits nothing rather than silently disabling the binding. That
// makes a wiring bug a loud, counted outage instead of a quiet loss of the
// security property — the same choice #4163 made for an empty allow-set.
func TestPendingTable_NilFailsClosed(t *testing.T) {
	var tbl *pendingTable
	k := pendingKey{xid: dhcpv4.TransactionID{5, 5, 5, 5}, hlen: 6}
	tbl.insert(k) // must not panic
	if tbl.matches(k) {
		t.Error("a nil pending table admitted a reply — the binding would be silently disabled")
	}
	if tbl.evictions() != 0 || tbl.occupancy() != 0 {
		t.Error("nil table reported nonzero counters")
	}
}

// TestPendingKeyFor_RequestAndReplyAgree proves the key survives the round
// trip: the relay stamps hops/giaddr/Option 82 on the way up, and RFC 2131
// §4.3.1 Table 3 has the server echo xid+chaddr on the way down, so the key
// computed from the forwarded request must equal the key computed from the
// reply. If this drifts, every reply is dropped.
func TestPendingKeyFor_RequestAndReplyAgree(t *testing.T) {
	chaddr := net.HardwareAddr{0x02, 0, 0, 0, 0, 7}
	req := newRequest(t, dhcpv4.MessageTypeDiscover, chaddr, nil)
	before := pendingKeyFor(req)

	// Apply exactly the mutations the relay makes to a first-hop request.
	req.HopCount++
	req.GatewayIPAddr = net.IPv4(10, 0, 0, 254)
	addOption82(req, "ge-0-0-0")
	if got := pendingKeyFor(req); got != before {
		t.Error("relay stamping changed the binding key — replies would never match")
	}

	// And the server's reply, built per Table 3, yields the same key.
	reply := serverReply(t, req, dhcpv4.MessageTypeOffer, net.IPv4(10, 0, 0, 5), nil, true)
	if got := pendingKeyFor(reply); got != before {
		t.Error("the server-echoed reply key does not match the request key")
	}
}

// TestPendingKeyFor_OversizeChaddrDoesNotPanic guards the defensive cap in
// pendingKeyFor. dhcpv4.FromBytes clamps a parsed chaddr to 16 bytes, but a
// packet constructed in-process is not bound by that, and a panic in the relay
// read loop would take the relay down.
func TestPendingKeyFor_OversizeChaddrDoesNotPanic(t *testing.T) {
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	pkt.ClientHWAddr = make(net.HardwareAddr, 32)
	for i := range pkt.ClientHWAddr {
		pkt.ClientHWAddr[i] = byte(i)
	}
	k := pendingKeyFor(pkt)
	if k.hlen != 16 {
		t.Errorf("hlen = %d, want 16 (clamped)", k.hlen)
	}
}

// TestManagerRelay_HasPendingTable guards the wiring the fail-closed posture
// depends on: because a nil table drops every reply, a manager-built relay MUST
// have one. Without this, a future refactor that forgets the field would break
// DHCP entirely and no other test would say why.
func TestManagerRelay_HasPendingTable(t *testing.T) {
	client := newFakeConn()
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)
	m.Apply(context.Background(), singleInterfaceConfig())
	defer m.Stop()

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.relays) == 0 {
		t.Fatal("no relay started")
	}
	for name, ir := range m.relays {
		if ir.pending == nil {
			t.Errorf("relay %q has a nil pending table — every reply would be dropped", name)
		}
	}
}

// defaultTestPendingCap is the capacity a default-rate relay gets. Tests that
// only need "a table big enough not to interfere" use it rather than a literal.
func defaultTestPendingCap() int {
	c, _ := pendingCapacityFor(defaultMaxPacketRate)
	return c
}

// TestPendingCapacity_TracksMaxPacketRate is the #6603-F1 fail-on-revert guard.
// It pins the PROPERTY — a reply arriving one server-RTT after its request must
// still bind at a raised `overrides maximum-packet-rate` — not the capacity
// number.
//
// The regression it guards: capacity used to be a hardcoded 8192 while the fill
// rate is the configurable maxPacketRate, so steady-state occupancy
// (rate x pendingTTL) exceeded capacity above ~273 pps and the effective
// binding window collapsed from 30s to 8192/rate seconds. On a segment
// provisioned at 3000 pps — which the relay's own README recommends for a busy
// segment — the window collapsed to 2.7s, so a boot storm against a saturated
// server (RTT > 2.7s) had every reply dropped at the relay: a completed storm
// turned into a permanent retry storm.
//
// Reverting pendingCapacityFor to a fixed 8192 makes this RED as an assertion:
// the victim's binding is evicted by the intervening traffic and the reply that
// arrives one RTT later no longer matches.
func TestPendingCapacity_TracksMaxPacketRate(t *testing.T) {
	const (
		rate      = 3000     // operator raised maximum-packet-rate
		rttPacket = rate * 3 // 3 seconds of traffic while the server thinks
		oldFixed  = 8192     // the pre-fix hardcoded capacity
	)
	// The scenario is only meaningful if the intervening traffic would have
	// overflowed the OLD fixed capacity; otherwise the test proves nothing.
	if rttPacket <= oldFixed {
		t.Fatalf("test is vacuous: %d intervening inserts do not exceed the old cap %d",
			rttPacket, oldFixed)
	}

	capacity, clamped := pendingCapacityFor(rate)
	if clamped {
		t.Fatalf("capacity for %d pps was clamped (%d) — the ceiling must not bind "+
			"at a realistic campus rate", rate, capacity)
	}
	now := time.Unix(5000, 0)
	tbl := newPendingTable(capacity, pendingTTL, func() time.Time { return now })

	// A client's request goes upstream.
	victim := pendingKey{xid: dhcpv4.TransactionID{0xDE, 0xAD, 0xBE, 0xEF}, hlen: 6}
	tbl.insert(victim)

	// The server is saturated; meanwhile the segment keeps offering traffic at
	// the configured rate for one server RTT (3s, inside the 30s TTL).
	for i := 0; i < rttPacket; i++ {
		tbl.insert(pendingKey{
			xid:  dhcpv4.TransactionID{byte(i), byte(i >> 8), byte(i >> 16), 0x01},
			hlen: 6,
		})
	}
	now = now.Add(3 * time.Second)

	// The OFFER finally arrives, still well inside the 30s binding window.
	if !tbl.matches(victim) {
		t.Errorf("a reply arriving %s after its request no longer binds at %d pps "+
			"(capacity %d, %d intervening requests, evictions %d) — the binding "+
			"window collapsed and legitimate DHCP is being dropped",
			3*time.Second, rate, capacity, rttPacket, tbl.evictions())
	}
	if got := tbl.evictions(); got != 0 {
		t.Errorf("evictions = %d, want 0 — a correctly-sized table must not evict "+
			"within one TTL of legitimate rate-limited traffic", got)
	}
}

// TestPendingCapacity_Derivation pins the sizing rule and its bounds: capacity
// covers the sustained window plus the token bucket's burst, never drops below
// the floor, and is clamped (with the clamp REPORTED) at the memory ceiling so
// the derivation cannot itself become a memory-exhaustion vector.
func TestPendingCapacity_Derivation(t *testing.T) {
	ttlSecs := int(pendingTTL / time.Second)

	for _, rate := range []int{1, 50, defaultMaxPacketRate, 500, 3000} {
		capacity, clamped := pendingCapacityFor(rate)
		if clamped {
			t.Errorf("rate %d: unexpectedly clamped at capacity %d", rate, capacity)
		}
		if capacity < pendingCapMin {
			t.Errorf("rate %d: capacity %d below the floor %d", rate, capacity, pendingCapMin)
		}
		// Must hold a full TTL of rate-limited traffic (the whole point).
		if want := rate * ttlSecs; capacity < want {
			t.Errorf("rate %d: capacity %d < rate*TTL %d — the window would collapse",
				rate, capacity, want)
		}
	}

	// Ceiling: the schema allows up to 1000000 pps; an unclamped derivation
	// would be ~3e7 entries (gigabytes).
	capacity, clamped := pendingCapacityFor(1000000)
	if !clamped {
		t.Error("1000000 pps was not reported as clamped")
	}
	if capacity != pendingCapMax {
		t.Errorf("capacity at 1000000 pps = %d, want the ceiling %d", capacity, pendingCapMax)
	}
	// And the clamp must be reported with an honest effective window.
	if w := pendingWindow(capacity, 1000000); w >= pendingTTL {
		t.Errorf("effective window at the ceiling = %v, want < nominal %v", w, pendingTTL)
	}

	// A nonsense rate from a hand-edited active.json must not overflow. Use a
	// value representable in a 32-bit int: an untyped constant that overflows
	// int on GOARCH=386 fails to COMPILE, which would break 32-bit builds
	// rather than test the guard.
	if c, cl := pendingCapacityFor(1 << 30); !cl || c != pendingCapMax {
		t.Errorf("absurd rate: capacity=%d clamped=%v, want %d/true", c, cl, pendingCapMax)
	}
	// Unset/negative falls back to the default rate, not to zero capacity.
	if c, _ := pendingCapacityFor(0); c < pendingCapMin {
		t.Errorf("unset rate: capacity %d below floor %d", c, pendingCapMin)
	}
}

// TestManagerRelay_PendingCapacityFollowsOverride pins the WIRING: the relay
// the manager builds must size its table from the interface's resolved
// maximum-packet-rate, not from a constant. Without this the derivation could
// be correct and simply not plumbed in.
func TestManagerRelay_PendingCapacityFollowsOverride(t *testing.T) {
	cfg := singleInterfaceConfig()
	cfg.Groups["g"].MaximumPacketRate = 3000

	client := newFakeConn()
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)
	m.Apply(context.Background(), cfg)
	defer m.Stop()

	want, _ := pendingCapacityFor(3000)
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, ir := range m.relays {
		if got := ir.pending.capacity(); got != want {
			t.Errorf("relay %q pending capacity = %d, want %d (derived from "+
				"maximum-packet-rate 3000)", name, got, want)
		}
		if ir.pendingClamped {
			t.Errorf("relay %q reported a clamp at 3000 pps", name)
		}
	}
}

// TestPendingTable_AtCapInsertIsConstantTime pins the O(1) invariant of the
// at-capacity insert path deterministically — by counting ring slots examined,
// not by timing, so it cannot flake.
//
// The regression it guards: the original implementation ranged the ENTIRE map
// to find the minimum expiry, and did so twice per admitted packet once full
// (a reap sweep plus an evict scan). That is O(capacity) per packet on the
// single client-facing read goroutine — hundreds of microseconds per packet at
// a raised rate, saturating a core during exactly the overload the table is
// meant to survive. Because every entry carries the SAME ttl, insertion order
// IS expiry order, so the oldest is always at the ring head and no scan is
// needed.
func TestPendingTable_AtCapInsertIsConstantTime(t *testing.T) {
	now := time.Unix(7000, 0)
	clock := func() time.Time { return now }
	const capacity = 2048
	tbl := newPendingTable(capacity, time.Hour, clock) // long TTL: force CAP pressure

	key := func(i int) pendingKey {
		return pendingKey{
			xid:  dhcpv4.TransactionID{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)},
			hlen: 6,
		}
	}
	for i := 0; i < capacity; i++ {
		tbl.insert(key(i))
	}
	if tbl.occupancy() != capacity {
		t.Fatalf("occupancy = %d, want %d", tbl.occupancy(), capacity)
	}

	// Now every insert is at capacity and must evict exactly one entry.
	const atCapInserts = 4096
	before := tbl.scans()
	for i := 0; i < atCapInserts; i++ {
		tbl.insert(key(capacity + i))
	}
	scans := tbl.scans() - before

	// LOWER bound first, and it is load-bearing. Each at-cap insert must free a
	// slot through the ring, so scans must be at LEAST one per insert. Without
	// this, an implementation that abandons the ring for a map scan reports
	// zero scans and would sail past the upper bound alone — the test would
	// pass for the wrong reason. (Verified: reverting the eviction to the
	// original minimum-expiry map scan leaves the upper bound green and is
	// caught only here.)
	if scans < uint64(atCapInserts) {
		t.Errorf("at-cap inserts examined only %d ring slots for %d inserts; each "+
			"at-cap insert must free a slot through the ring. The eviction path "+
			"is bypassing the ring, so this test can no longer see its cost.",
			scans, atCapInserts)
	}
	// O(1) means a small constant per insert. O(capacity) would be
	// atCapInserts*capacity = 8388608. Allow generous slack (4x) so the bound
	// still fails loudly on any return to scanning.
	if maxScans := uint64(atCapInserts * 4); scans > maxScans {
		t.Errorf("at-cap inserts examined %d ring slots for %d inserts (%.1f per insert); "+
			"want O(1) (<= %d total). The eviction path has regressed to a scan.",
			scans, atCapInserts, float64(scans)/float64(atCapInserts), maxScans)
	}
	if got := tbl.evictions(); got != atCapInserts {
		t.Errorf("evictions = %d, want %d (one per at-cap insert)", got, atCapInserts)
	}
	if tbl.occupancy() != capacity {
		t.Errorf("occupancy = %d, want %d — the table must stay bounded", tbl.occupancy(), capacity)
	}
}

// TestPendingTable_DuplicateKeyDoesNotGrowRing pins the ring/map invariant for
// a repeated key: a client retransmitting the same xid (or the SELECTING
// REQUEST reusing the DISCOVER's xid) adds a ring slot each time while the map
// keeps one entry. The stale slots must be reclaimed for free rather than
// pushing the structures past capacity or evicting live entries.
func TestPendingTable_DuplicateKeyDoesNotGrowRing(t *testing.T) {
	now := time.Unix(8000, 0)
	clock := func() time.Time { return now }
	const capacity = 64
	tbl := newPendingTable(capacity, time.Hour, clock)

	dup := pendingKey{xid: dhcpv4.TransactionID{7, 7, 7, 7}, hlen: 6}
	for i := 0; i < capacity*8; i++ {
		tbl.insert(dup)
		now = now.Add(time.Millisecond) // distinct expiries, as a real clock gives
	}
	if got := tbl.liveEntries(); got != 1 {
		t.Errorf("size = %d, want 1 — a repeated key must not accumulate entries", got)
	}
	if !tbl.matches(dup) {
		t.Error("the repeated key no longer binds")
	}
	if got := tbl.capacity(); got != capacity {
		t.Errorf("capacity = %d, want %d (the ring must not grow)", got, capacity)
	}
	// Stale slots are reclaimed, so a fresh key must still be admitted without
	// evicting the live one.
	fresh := pendingKey{xid: dhcpv4.TransactionID{1, 1, 1, 1}, hlen: 6}
	tbl.insert(fresh)
	if !tbl.matches(fresh) || !tbl.matches(dup) {
		t.Error("a fresh key evicted the live duplicate, or was not admitted")
	}
}

// TestRelay_RateChangePreservesBindings is the fail-on-revert guard for the
// #6603 re-review MAJOR: a day-2 config change must NOT destroy outstanding
// request bindings.
//
// maxPacketRate participates in relaySpec.equal(), so changing it stops the
// relay and builds a replacement with a brand-new table. Because the
// replacement rebinds the SAME giaddr:67, replies for pre-reload requests still
// arrive — and without migration they are then dropped by the binding gate,
// which pre-#6562 would have been forwarded.
//
// It bites hardest for exactly this knob: raising maximum-packet-rate is the
// documented remedy for a busy segment, so an operator following the docs
// DURING a boot storm would flush every in-flight binding and trigger the retry
// storm the binding table exists to prevent.
//
// Removing the phase-2.5 snapshot/adopt migration in Apply makes this RED as an
// assertion: the OFFER is no longer delivered after the reload.
func TestRelay_RateChangePreservesBindings(t *testing.T) {
	h := newBindingHarness(t)
	defer h.stop()

	chaddr := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x5A}

	// A client's DISCOVER goes upstream and arms a binding.
	discover := newRequest(t, dhcpv4.MessageTypeDiscover, chaddr, nil)
	h.relayUp(discover)

	before := h.relay()
	if !before.pending.matches(pendingKeyFor(discover)) {
		t.Fatal("precondition: the relayed DISCOVER did not arm a binding")
	}

	// The operator raises maximum-packet-rate mid-storm — the documented
	// remedy. This restarts the relay with a larger table.
	cfg := singleInterfaceConfig()
	cfg.Groups["g"].MaximumPacketRate = 3000
	h.m.Apply(context.Background(), cfg)

	after := h.relay()
	if after == before {
		t.Fatal("precondition: the rate change did not restart the relay, so this " +
			"test is not exercising the migration path")
	}
	if got, want := after.pending.capacity(), mustCapacity(3000); got != want {
		t.Fatalf("precondition: replacement capacity = %d, want %d", got, want)
	}

	// The binding must have survived into the replacement table.
	if !after.pending.matches(pendingKeyFor(discover)) {
		t.Error("the outstanding binding was destroyed by the rate change — the " +
			"server's OFFER will now be dropped, turning the boot storm the " +
			"operator was mitigating into a retry storm")
	}

	if got := after.repliesDroppedNoRequest.Load(); got != 0 {
		t.Errorf("repliesDroppedNoRequest = %d, want 0 — a legitimate pre-reload "+
			"reply must not be dropped by the reload", got)
	}
}

// TestRelay_RateChangePreservesBindings_EndToEnd is the same MAJOR guard driven
// all the way through the sockets: the server's OFFER for a PRE-reload DISCOVER
// must still be delivered to the client after the relay restarts on a rate
// change.
//
// It cannot use bindingHarness, because the restart opens FRESH conns from the
// factory — the harness's original pair belongs to the dead session. A tracking
// factory hands out a new fakeConn per open and exposes the latest pair, so the
// test can drive the post-restart session.
func TestRelay_RateChangePreservesBindings_EndToEnd(t *testing.T) {
	tr := &connTracker{}
	m := testManager(tr.factory)
	m.Apply(context.Background(), singleInterfaceConfig())
	defer m.Stop()

	chaddr := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x6B}
	yiaddr := net.IPv4(10, 0, 0, 92)

	// Pre-reload: relay a DISCOVER through the FIRST session.
	client, server := tr.pairAfter(t, 2)
	discover := newRequest(t, dhcpv4.MessageTypeDiscover, chaddr, nil)
	before := server.writeCount()
	client.push(discover.ToBytes())
	if !waitFor(func() bool { return server.writeCount() > before }) {
		t.Fatal("precondition: the DISCOVER was not relayed upstream")
	}

	// The operator raises maximum-packet-rate: the relay restarts.
	cfg := singleInterfaceConfig()
	cfg.Groups["g"].MaximumPacketRate = 3000
	m.Apply(context.Background(), cfg)

	// Post-reload: the OFFER arrives on the NEW server socket (same giaddr:67).
	client2, server2 := tr.pairAfter(t, 4)
	if server2 == server {
		t.Fatal("precondition: the restart did not open a new server conn")
	}
	offer := serverReply(t, discover, dhcpv4.MessageTypeOffer, yiaddr, nil, true)
	server2.push(offer.ToBytes())

	if !waitFor(func() bool { return client2.writeCount() > 0 }) {
		t.Fatal("the OFFER answering a PRE-reload DISCOVER was not delivered to the " +
			"client after the rate change — the reload destroyed the binding, so " +
			"the boot storm the operator was mitigating becomes a retry storm")
	}
}

// connTracker is a packetConnFactory that returns a fresh fakeConn per open and
// remembers them, so a test can reach the conns of the CURRENT session after a
// relay restart. Conns are opened client-first then server, so the latest pair
// is the last two.
type connTracker struct {
	mu    sync.Mutex
	conns []*fakeConn
}

func (ct *connTracker) factory(ctx context.Context, ifaceName string,
	reusePort, broadcast bool, bindAddr *net.UDPAddr) (net.PacketConn, error) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	c := newFakeConn()
	// Odd opens are the server-facing conn; report a CONFIGURED server source so
	// replies pass the #4163 check.
	if len(ct.conns)%2 == 1 {
		c.srcAddr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: relayPort}
	}
	ct.conns = append(ct.conns, c)
	return c, nil
}

// pairAfter returns the (client, server) conns of the most recent session,
// waiting until at least want conns have been opened in total. The count is
// explicit because a restarted relay opens its conns ASYNCHRONOUSLY from its
// supervisor goroutine — Apply returns before they exist, so "latest" without a
// floor would hand back the DEAD session's pair.
func (ct *connTracker) pairAfter(t *testing.T, want int) (*fakeConn, *fakeConn) {
	t.Helper()
	var client, server *fakeConn
	ok := waitFor(func() bool {
		ct.mu.Lock()
		defer ct.mu.Unlock()
		if len(ct.conns) < want || len(ct.conns)%2 != 0 {
			return false
		}
		client, server = ct.conns[len(ct.conns)-2], ct.conns[len(ct.conns)-1]
		return true
	})
	if !ok {
		t.Fatalf("relay never opened %d conns (client+server per session)", want)
	}
	return client, server
}

// mustCapacity is pendingCapacityFor's capacity, for test preconditions.
func mustCapacity(rate int) int {
	c, _ := pendingCapacityFor(rate)
	return c
}

// TestPendingTable_AdoptShrinkEvictsOldestAndCounts pins the other direction of
// the migration: LOWERING maximum-packet-rate gives a smaller table, so some
// bindings cannot be carried. The excess must be dropped oldest-first (the same
// policy the steady-state path uses) and COUNTED, so a shrink is visible in
// PendingEvicted rather than silently discarding bindings.
func TestPendingTable_AdoptShrinkEvictsOldestAndCounts(t *testing.T) {
	now := time.Unix(9000, 0)
	clock := func() time.Time { return now }
	old := newPendingTable(8, time.Hour, clock)

	key := func(n byte) pendingKey {
		return pendingKey{xid: dhcpv4.TransactionID{0, 0, 0, n}, hlen: 6}
	}
	for i := byte(1); i <= 8; i++ {
		old.insert(key(i))
		now = now.Add(time.Second)
	}

	live := old.snapshot()
	if len(live) != 8 {
		t.Fatalf("snapshot returned %d live bindings, want 8", len(live))
	}

	// Replacement holds only 3.
	small := newPendingTable(3, time.Hour, clock)
	small.adopt(live)

	if got := small.occupancy(); got != 3 {
		t.Errorf("occupancy = %d, want 3 (the replacement's capacity)", got)
	}
	if got := small.evictions(); got != 5 {
		t.Errorf("evictions = %d, want 5 — a shrink must COUNT the bindings it "+
			"cannot carry, not discard them silently", got)
	}
	// The NEWEST three (6,7,8) survive — they have the longest remaining life.
	for _, n := range []byte{6, 7, 8} {
		if !small.matches(key(n)) {
			t.Errorf("binding %d did not survive the shrink; the newest must be kept", n)
		}
	}
	for _, n := range []byte{1, 2, 3, 4, 5} {
		if small.matches(key(n)) {
			t.Errorf("binding %d survived; the OLDEST must be evicted first", n)
		}
	}
}

// TestPendingTable_SnapshotExcludesExpiredAndPreservesExpiry pins two migration
// invariants: an already-expired binding is not resurrected by a reload, and a
// carried binding keeps its ORIGINAL expiry. Refreshing the TTL on reload would
// silently extend the attacker's xid-guessing window every time the operator
// touched the config.
func TestPendingTable_SnapshotExcludesExpiredAndPreservesExpiry(t *testing.T) {
	now := time.Unix(9500, 0)
	clock := func() time.Time { return now }
	old := newPendingTable(16, 30*time.Second, clock)

	stale := pendingKey{xid: dhcpv4.TransactionID{1, 0, 0, 0}, hlen: 6}
	fresh := pendingKey{xid: dhcpv4.TransactionID{2, 0, 0, 0}, hlen: 6}
	old.insert(stale)
	now = now.Add(25 * time.Second)
	old.insert(fresh) // 25s newer

	now = now.Add(6 * time.Second) // stale is now 31s old (expired); fresh is 6s old

	live := old.snapshot()
	if len(live) != 1 || live[0].key != fresh {
		t.Fatalf("snapshot = %d entries, want just the unexpired one", len(live))
	}

	replacement := newPendingTable(16, 30*time.Second, clock)
	replacement.adopt(live)

	if replacement.matches(stale) {
		t.Error("an EXPIRED binding was resurrected by the migration")
	}
	if !replacement.matches(fresh) {
		t.Fatal("the live binding did not survive the migration")
	}
	// Original expiry preserved: fresh was inserted 6s ago with a 30s TTL, so it
	// must lapse 24s from now — NOT 30s (which would mean the reload refreshed
	// it and widened the guessing window).
	now = now.Add(25 * time.Second)
	if replacement.matches(fresh) {
		t.Error("the carried binding outlived its ORIGINAL expiry — a config reload " +
			"must not refresh the TTL and extend the binding window")
	}
}

// TestPendingTable_EqualExpiriesDoNotLoseBinding is the fail-on-revert guard for
// the #6603 re-review MINOR 1: slot identity must be the generation counter, not
// the expiry timestamp.
//
// Two inserts of the same key can receive the SAME expiry — nothing guarantees
// time.Now() advances between two calls. With expiry-as-identity, popping the
// OLDER slot at capacity matches the map entry the NEWER slot owns and deletes
// it, silently losing a live binding. The clock here is FROZEN so equal
// expiries are the case under test rather than the case avoided.
//
// Reverting popHeadLocked to compare expiries makes this RED.
func TestPendingTable_EqualExpiriesDoNotLoseBinding(t *testing.T) {
	frozen := time.Unix(10000, 0)
	clock := func() time.Time { return frozen } // never advances
	const capacity = 4
	tbl := newPendingTable(capacity, time.Hour, clock)

	dup := pendingKey{xid: dhcpv4.TransactionID{3, 3, 3, 3}, hlen: 6}
	other := func(n byte) pendingKey {
		return pendingKey{xid: dhcpv4.TransactionID{9, 9, 9, n}, hlen: 6}
	}

	// Two inserts of the same key under a frozen clock => identical expiries,
	// two ring slots, one map entry.
	tbl.insert(dup)
	tbl.insert(dup)
	if got := tbl.liveEntries(); got != 1 {
		t.Fatalf("precondition: liveEntries = %d, want 1", got)
	}
	if got := tbl.occupancy(); got != 2 {
		t.Fatalf("precondition: occupancy = %d, want 2 (two ring slots)", got)
	}

	// Fill the rest, then push past capacity so the OLDER duplicate slot is
	// popped. It is stale, so the binding must survive.
	tbl.insert(other(1))
	tbl.insert(other(2))
	tbl.insert(other(3)) // at capacity: pops the older dup slot

	if !tbl.matches(dup) {
		t.Error("the binding was lost when its STALE duplicate slot was popped — " +
			"slot identity is being inferred from the expiry, which two inserts " +
			"can share")
	}
}

// TestPendingTable_OccupancyTracksRingNotMap is the fail-on-revert guard for the
// #6603 re-review MINOR 2: the operator-facing gauge must report RING pressure,
// because that is what governs eviction.
//
// Duplicate inserts consume ring slots without adding map entries, so
// len(entries) under-reports: a capacity-4 ring holding A,B,B,B has
// len(entries)==2 while the very next insert must evict live A. Reporting
// len(entries) would show a comfortable 2/4 at the exact moment eviction
// begins — the opposite of the documented contract.
//
// Pointing PendingSize back at len(entries) makes this RED.
func TestPendingTable_OccupancyTracksRingNotMap(t *testing.T) {
	now := time.Unix(11000, 0)
	clock := func() time.Time { return now }
	const capacity = 4
	tbl := newPendingTable(capacity, time.Hour, clock)

	a := pendingKey{xid: dhcpv4.TransactionID{0xA, 0, 0, 0}, hlen: 6}
	b := pendingKey{xid: dhcpv4.TransactionID{0xB, 0, 0, 0}, hlen: 6}

	tbl.insert(a)
	for i := 0; i < 3; i++ {
		tbl.insert(b) // three slots, one entry
		now = now.Add(time.Millisecond)
	}

	if got := tbl.liveEntries(); got != 2 {
		t.Fatalf("precondition: liveEntries = %d, want 2 (A and B)", got)
	}
	if got := tbl.occupancy(); got != capacity {
		t.Errorf("occupancy = %d, want %d — the gauge must report RING slots. "+
			"Reporting the %d map entries would show a comfortable %d/%d at the "+
			"exact moment the next insert evicts live A.",
			got, capacity, tbl.liveEntries(), tbl.liveEntries(), capacity)
	}

	// Confirm the premise: the next insert really does evict.
	tbl.insert(pendingKey{xid: dhcpv4.TransactionID{0xC, 0, 0, 0}, hlen: 6})
	if got := tbl.evictions(); got == 0 {
		t.Error("premise failed: the table was full but the next insert did not evict")
	}
	if tbl.matches(a) {
		t.Error("premise failed: A should have been the evicted (oldest) entry")
	}
}

// TestPendingTable_FullDrainIsConstantTime is the fail-on-revert guard for the
// #6603 re-review MINOR 4: reclaiming an ENTIRELY expired table must not walk
// it slot by slot.
//
// The ring is expiry-ordered, so once the newest slot has expired every slot
// has. Popping them one at a time is up to pendingCapMax (131072) iterations,
// each with a map lookup and delete, under the mutex on the client-facing
// packet path — a multi-millisecond stall that also blocks the reply loop, on
// the first insert after any idle period. The fast path takes that case in
// constant time.
//
// Scans are counted rather than timed, so this cannot flake. Removing the
// fast path makes it RED as an assertion: the drain examines one slot per
// entry instead of a single probe.
func TestPendingTable_FullDrainIsConstantTime(t *testing.T) {
	now := time.Unix(12000, 0)
	clock := func() time.Time { return now }
	const capacity = 2048
	tbl := newPendingTable(capacity, 30*time.Second, clock)

	key := func(i int) pendingKey {
		return pendingKey{
			xid:  dhcpv4.TransactionID{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)},
			hlen: 6,
		}
	}
	for i := 0; i < capacity; i++ {
		tbl.insert(key(i))
	}
	if got := tbl.occupancy(); got != capacity {
		t.Fatalf("precondition: occupancy = %d, want %d", got, capacity)
	}

	// Idle past the TTL: EVERY slot is now expired.
	now = now.Add(time.Hour)

	before := tbl.scans()
	tbl.insert(key(capacity)) // the first insert after the idle period
	scans := tbl.scans() - before

	// A per-slot drain would examine ~capacity slots. Allow a small constant.
	if scans > 8 {
		t.Errorf("the first insert after an idle period examined %d ring slots "+
			"for a %d-entry table; a fully expired ring must be reclaimed in "+
			"constant time, not popped slot by slot under the mutex on the "+
			"packet path", scans, capacity)
	}

	// The reclaim must be REAL, not just cheap: the table now holds only the
	// new key, and the expired ones must be gone from both structures.
	if got := tbl.occupancy(); got != 1 {
		t.Errorf("occupancy after the drain = %d, want 1 (only the new insert)", got)
	}
	if got := tbl.liveEntries(); got != 1 {
		t.Errorf("liveEntries after the drain = %d, want 1 — the expired keys are "+
			"still in the map", got)
	}
	if !tbl.matches(key(capacity)) {
		t.Error("the newly inserted binding did not survive the drain")
	}
	if tbl.matches(key(0)) {
		t.Error("an expired binding survived the drain")
	}
	// A wholesale drain is EXPIRY, not cap pressure: it must not be counted as
	// an eviction, or an idle relay would look like it was shedding load.
	if got := tbl.evictions(); got != 0 {
		t.Errorf("evictions = %d, want 0 — expiry is not cap-pressure eviction", got)
	}
}

// TestPendingTable_AdoptRequiresEmptyDestination pins the precondition that
// makes adopt safe.
//
// adopt APPENDS; it does not merge. Migrated slots carry the old table's
// expiries, so appending them onto a non-empty ring can place an EARLIER expiry
// after a later one and destroy the expiry ordering that every other operation
// depends on. The concrete corruption: a ring of
// dst(+4s), dst(+4s), migrated(+2s), migrated(+3s) is no longer ordered, so at
// t=+3.5s the full-drain probe reads the NEWEST slot (migrated, +3s), finds it
// expired, concludes the whole ring has expired, and wipes the two destination
// bindings that are live until +4s. The head drain and occupancy's binary
// search would mis-locate the boundary the same way.
//
// The sole production caller adopts into a table built moments earlier, so this
// cannot fire in the live path; the assertion exists so a future second caller
// fails loudly instead of silently corrupting the structure that decides which
// replies reach clients.
func TestPendingTable_AdoptRequiresEmptyDestination(t *testing.T) {
	now := time.Unix(13000, 0)
	clock := func() time.Time { return now }
	key := func(n byte) pendingKey {
		return pendingKey{xid: dhcpv4.TransactionID{0, 0, 0, n}, hlen: 6}
	}

	src := newPendingTable(8, 2*time.Second, clock)
	src.insert(key(1))
	now = now.Add(time.Second)
	src.insert(key(2))
	live := src.snapshot()
	if len(live) != 2 {
		t.Fatalf("precondition: snapshot = %d, want 2", len(live))
	}

	// Destination already holds bindings with LATER expiries than the migrated
	// ones — exactly the ordering-breaking case.
	dst := newPendingTable(4, time.Hour, clock)
	dst.insert(key(0xE1))
	dst.insert(key(0xE2))

	defer func() {
		if recover() == nil {
			t.Error("adopt into a NON-EMPTY destination did not panic; appending " +
				"migrated expiries onto existing ones breaks the ring's expiry " +
				"ordering, after which the full-drain probe can wipe live bindings")
		}
	}()
	dst.adopt(live)
}

// TestPendingTable_PartialDrainIsBounded is the binder for the adjacent case the
// full-drain fast path does NOT cover: MOST slots expired with the newest still
// live.
//
// The failing input is STAGGERED expiries. The previous guard froze the clock,
// so every slot shared one expiry and the ring was always either wholly expired
// (fast path) or wholly live — the mixed case could not be constructed, and the
// unbounded loop it exercises was invisible. Here the clock advances during the
// fill, then stops just short of the newest slot's expiry: the probe reads a
// LIVE newest slot, the fast path declines, and an unbounded drain would pop
// capacity-1 slots one at a time under the mutex on the packet path.
//
// Removing the maxDrainPerInsert bound makes this RED.
func TestPendingTable_PartialDrainIsBounded(t *testing.T) {
	base := time.Unix(14000, 0)
	now := base
	clock := func() time.Time { return now }
	const capacity = 4096
	const ttl = 30 * time.Second
	tbl := newPendingTable(capacity, ttl, clock)

	key := func(i int) pendingKey {
		return pendingKey{
			xid:  dhcpv4.TransactionID{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)},
			hlen: 6,
		}
	}
	// Stagger: one insert per millisecond, so expiries are strictly increasing.
	for i := 0; i < capacity; i++ {
		tbl.insert(key(i))
		now = now.Add(time.Millisecond)
	}
	// Advance so that every slot EXCEPT the newest handful has expired. The
	// newest slot was inserted at base+(capacity-1)ms and expires at
	// +ttl; stop one millisecond short of that.
	now = base.Add(ttl).Add(time.Duration(capacity-2) * time.Millisecond)

	// Precondition: the ring is in the MIXED state, not wholly expired.
	if got := tbl.occupancy(); got == 0 || got == capacity {
		t.Fatalf("precondition: occupancy = %d, want a mixed ring (0 < n < %d) — "+
			"this test is meaningless if the ring is wholly expired or wholly live",
			got, capacity)
	}

	before := tbl.scans()
	tbl.insert(key(capacity)) // the late request after the quiet period
	scans := tbl.scans() - before

	// An unbounded drain would examine ~capacity slots. The bound is
	// maxDrainPerInsert plus the single eviction pop.
	if maxScans := uint64(maxDrainPerInsert + 4); scans > maxScans {
		t.Errorf("a single insert into a mostly-expired ring examined %d slots "+
			"(capacity %d); per-insert reclaim must be bounded by ~%d, or one "+
			"late packet stalls the relay under the mutex",
			scans, capacity, maxScans)
	}
	// The new binding must still be present — bounding the drain must not have
	// cost correctness.
	if !tbl.matches(key(capacity)) {
		t.Error("the newly inserted binding is missing after a bounded drain")
	}
}

// TestPendingTable_OccupancyExcludesExpired is the binder for the false-HIGH
// gauge.
//
// The failing input is simply TIME PASSING WITHOUT AN INSERT: expired slots stay
// counted in the raw ring `count` until some later insert reclaims them, so an
// idle full table reported capacity/capacity even though the very next insert
// reclaims the lot and evicts nothing. An operator following the documented
// advice to alert on the occupancy ratio would be paged by a relay that is
// merely quiet.
//
// Reverting occupancy to return the raw count makes this RED.
func TestPendingTable_OccupancyExcludesExpired(t *testing.T) {
	now := time.Unix(15000, 0)
	clock := func() time.Time { return now }
	const capacity = 64
	const ttl = 30 * time.Second
	tbl := newPendingTable(capacity, ttl, clock)

	key := func(i int) pendingKey {
		return pendingKey{xid: dhcpv4.TransactionID{byte(i), byte(i >> 8), 0, 0}, hlen: 6}
	}
	// Fill the first half, then pause, then fill the second half, so the two
	// halves expire at clearly different times.
	for i := 0; i < capacity/2; i++ {
		tbl.insert(key(i))
	}
	now = now.Add(20 * time.Second)
	for i := capacity / 2; i < capacity; i++ {
		tbl.insert(key(i))
	}
	if got := tbl.occupancy(); got != capacity {
		t.Fatalf("precondition: occupancy = %d, want %d (ring full, all live)",
			got, capacity)
	}

	// Idle past the FIRST half's expiry only. No insert happens, so nothing is
	// reclaimed — the raw count is still `capacity`.
	now = now.Add(15 * time.Second)

	if got, want := tbl.occupancy(), capacity/2; got != want {
		t.Errorf("occupancy = %d, want %d — the gauge must exclude the expired "+
			"prefix. Reporting the raw ring count shows %d/%d on a relay that is "+
			"merely idle, and the next insert would reclaim them with no eviction.",
			got, want, capacity, capacity)
	}

	// And once everything has expired it must read empty, not full.
	now = now.Add(time.Hour)
	if got := tbl.occupancy(); got != 0 {
		t.Errorf("occupancy on a wholly expired idle table = %d, want 0", got)
	}
}

// TestPendingTable_IdleRelayReportsNoEvictions pins the operator-facing
// property that the two reclaim paths exist to protect: a relay that is merely
// IDLE must never report cap-pressure evictions.
//
// PendingEvicted is documented as damage already in progress, so it must not
// fire just because a quiet period left the ring full of expired slots. What
// keeps that true is that the fast path and the bounded drain always free room
// before the eviction loop can run — see the proof in insert().
//
// Scope note, stated because the distinction cost a round here: this does NOT
// bind an expiry check inside the eviction loop. Such a check is unreachable
// (whenever the loop runs the head is unexpired by construction), so a mutation
// that removed it could not be caught by any test — which is precisely why the
// code carries the proof instead of a defensive re-check. This test binds the
// reachable property: remove BOTH reclaim steps and expired slots reach the
// eviction loop and are counted, turning an idle relay into a false alarm.
func TestPendingTable_IdleRelayReportsNoEvictions(t *testing.T) {
	base := time.Unix(16000, 0)
	now := base
	clock := func() time.Time { return now }
	const capacity = maxDrainPerInsert * 4
	const ttl = 30 * time.Second
	tbl := newPendingTable(capacity, ttl, clock)

	key := func(i int) pendingKey {
		return pendingKey{xid: dhcpv4.TransactionID{byte(i), byte(i >> 8), 0, 0}, hlen: 6}
	}
	for i := 0; i < capacity; i++ {
		tbl.insert(key(i))
		now = now.Add(time.Millisecond)
	}
	// Expire everything except the newest slot: a mixed ring with a long
	// expired prefix, which is the state a quiet period leaves behind.
	now = base.Add(ttl).Add(time.Duration(capacity-2) * time.Millisecond)

	tbl.insert(key(capacity))

	if got := tbl.evictions(); got != 0 {
		t.Errorf("evictions = %d, want 0 — the slots reclaimed here had EXPIRED, "+
			"so an idle relay must not look like it is shedding load under cap "+
			"pressure", got)
	}
	// And the reclaim must have actually freed room, which is what makes the
	// eviction loop unreachable in this state.
	if got := tbl.occupancy(); got >= capacity {
		t.Errorf("occupancy = %d, want < capacity %d — the reclaim did not free "+
			"room, so the eviction loop would run against an expired head", got, capacity)
	}
}
