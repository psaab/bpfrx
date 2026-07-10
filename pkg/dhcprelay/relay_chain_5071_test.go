package dhcprelay

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// downstreamOption82 builds a raw Option 82 (Relay Agent Information) value as
// a real DOWNSTREAM relay would emit it: sub-option 1 (circuit-id) plus
// sub-option 2 (remote-id). The two-sub-option shape is deliberate — this
// relay's own addOption82 only ever writes sub-option 1, so if the chained
// path accidentally rebuilt the option the sub-option 2 (remote-id) bytes
// would disappear, making the preservation assertion catch an overwrite.
func downstreamOption82(circuitID, remoteID string) []byte {
	var b []byte
	// sub-option 1: circuit-id.
	b = append(b, suboption1CircuitID, byte(len(circuitID)))
	b = append(b, []byte(circuitID)...)
	// sub-option 2: remote-id (type 2).
	b = append(b, 2, byte(len(remoteID)))
	b = append(b, []byte(remoteID)...)
	return b
}

// runRelayForward pushes a single BOOTREQUEST through the live runRelay loop
// and returns the relayed datagram observed on the server conn. It fails the
// test if nothing is relayed within the deadline.
func runRelayForward(t *testing.T, req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	t.Helper()
	client := newFakeConn()
	client.pending = [][]byte{req.ToBytes()}
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)
	m.Apply(context.Background(), singleInterfaceConfig())
	defer m.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for server.writeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if server.writeCount() == 0 {
		t.Fatal("request was not relayed to the server within 2s")
	}
	relayed, err := dhcpv4.FromBytes(server.firstWrite(t))
	if err != nil {
		t.Fatalf("relayed datagram does not parse: %v", err)
	}
	return relayed
}

// TestRunRelay_FirstHopStampsGiaddrAndOption82 pins the first-hop path
// (inbound giaddr == 0): the relay stamps its own interface giaddr
// (10.0.0.254, from testManager's resolver) and inserts its circuit-id
// Option 82 (sub-option 1 == the interface name "ge-0-0-0"). This is the
// existing behavior and MUST NOT regress when the #5071 chained-preserve
// branch is added.
func TestRunRelay_FirstHopStampsGiaddrAndOption82(t *testing.T) {
	req, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	req.OpCode = dhcpv4.OpcodeBootRequest
	req.ClientHWAddr = net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	req.HopCount = 0
	// No giaddr, no Option 82: this relay is the first hop.
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))

	relayed := runRelayForward(t, req)

	if !relayed.GatewayIPAddr.Equal(net.IPv4(10, 0, 0, 254)) {
		t.Errorf("first-hop giaddr = %v, want 10.0.0.254 (relay stamps its own)",
			relayed.GatewayIPAddr)
	}
	if relayed.HopCount != 1 {
		t.Errorf("first-hop HopCount = %d, want 1", relayed.HopCount)
	}
	opt := relayed.Options.Get(option82)
	if opt == nil {
		t.Fatal("first-hop relay did not insert Option 82")
	}
	if opt[0] != suboption1CircuitID {
		t.Fatalf("Option 82 sub-option type = %d, want %d (circuit-id)",
			opt[0], suboption1CircuitID)
	}
	if circuitID := string(opt[2:]); circuitID != "ge-0-0-0" {
		t.Errorf("first-hop circuit-id = %q, want %q (interface name)",
			circuitID, "ge-0-0-0")
	}
}

// TestRunRelay_ChainedPreservesGiaddrAndOption82 is the #5071 RED-on-revert
// proof. A BOOTREQUEST that arrives with a NONZERO giaddr (203.0.113.9,
// stamped by a downstream relay) and a downstream relay-agent Option 82 must
// be forwarded with BOTH preserved untouched — the relay only increments the
// BOOTP hops field (RFC 1542 §4.1.1 / RFC 3046). Reverting the conditional
// preserve makes the relay stamp its own giaddr (10.0.0.254) and overwrite
// Option 82 with its own circuit-id, so both assertions go RED.
func TestRunRelay_ChainedPreservesGiaddrAndOption82(t *testing.T) {
	const downstreamGiaddr = "203.0.113.9"
	inbound82 := downstreamOption82("down-ckt-42", "aabbccddeeff")

	req, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	req.OpCode = dhcpv4.OpcodeBootRequest
	req.ClientHWAddr = net.HardwareAddr{0x02, 0, 0, 0, 0, 2}
	req.HopCount = 1 // one downstream relay already handled it
	req.GatewayIPAddr = net.ParseIP(downstreamGiaddr)
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))
	req.UpdateOption(dhcpv4.OptGeneric(option82, inbound82))

	relayed := runRelayForward(t, req)

	// giaddr preserved: equals the downstream relay's address, NOT this
	// relay's own giaddr (10.0.0.254).
	if !relayed.GatewayIPAddr.Equal(net.ParseIP(downstreamGiaddr)) {
		t.Errorf("chained giaddr = %v, want %s (downstream giaddr preserved); "+
			"if this is 10.0.0.254 the relay overwrote it (#5071 regression)",
			relayed.GatewayIPAddr, downstreamGiaddr)
	}

	// Option 82 preserved byte-for-byte: the downstream circuit-id AND
	// remote-id sub-options survive untouched.
	got := relayed.Options.Get(option82)
	if !bytes.Equal(got, inbound82) {
		t.Errorf("chained Option 82 = %v, want %v (downstream option preserved); "+
			"a mismatch means the relay Del/overwrote it (#5071 regression)",
			got, inbound82)
	}

	// hops incremented (the one field an intermediate relay may touch).
	if relayed.HopCount != 2 {
		t.Errorf("chained HopCount = %d, want 2 (incremented from 1)",
			relayed.HopCount)
	}
}

// TestRunRelay_ChainedHopLimitDrop proves the RFC 1542 §4.1.1 loop-protection
// hop limit still applies to a chained request (nonzero giaddr). A chained
// request whose hops field has reached the limit is dropped and counted,
// exactly like the first-hop path — the preserve branch must not smuggle a
// looping request past the cap.
func TestRunRelay_ChainedHopLimitDrop(t *testing.T) {
	req, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	req.OpCode = dhcpv4.OpcodeBootRequest
	req.ClientHWAddr = net.HardwareAddr{0x02, 0, 0, 0, 0, 3}
	req.HopCount = defaultMaxHopCount // at the default limit (16)
	req.GatewayIPAddr = net.ParseIP("203.0.113.9")
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))
	req.UpdateOption(dhcpv4.OptGeneric(option82,
		downstreamOption82("down-ckt", "aabbcc")))

	client := newFakeConn()
	client.pending = [][]byte{req.ToBytes()}
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)
	m.Apply(context.Background(), singleInterfaceConfig())
	defer m.Stop()

	// Wait for the loop to consume the datagram (second ReadFrom = post-drop).
	deadline := time.Now().Add(1 * time.Second)
	for client.readCalls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	if got := server.writeCount(); got != 0 {
		t.Fatalf("chained request at hop limit was relayed (%d datagram(s)), "+
			"want drop", got)
	}
	var dropped uint64
	for _, s := range m.Stats() {
		dropped += s.RequestsDroppedMaxHops
	}
	if dropped == 0 {
		t.Error("chained request dropped but RequestsDroppedMaxHops stayed 0")
	}
}
