package dhcprelay

import (
	"context"
	"net"
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
			got, pendingCap)
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
	tbl := newPendingTable(pendingCap, pendingTTL, time.Now)
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
	tbl := newPendingTable(pendingCap, 30*time.Second, clock)
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
	if tbl.size() != capacity {
		t.Fatalf("size = %d, want %d after filling to capacity", tbl.size(), capacity)
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
	if tbl.size() != capacity {
		t.Errorf("size = %d, want %d (the table must stay bounded)", tbl.size(), capacity)
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
	if tbl.evictions() != 0 || tbl.size() != 0 {
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
