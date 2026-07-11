package dhcprelay

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/psaab/xpf/pkg/config"
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
// on the DEFAULT (untrusted, client-facing) single-interface config and returns
// the relayed datagram observed on the server conn.
func runRelayForward(t *testing.T, req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	t.Helper()
	return runRelayForwardCfg(t, req, singleInterfaceConfig())
}

// runRelayForwardCfg pushes a single BOOTREQUEST through the live runRelay loop
// under an explicit relay config (so a test can toggle `overrides
// trust-option-82`, #5414) and returns the relayed datagram observed on the
// server conn. It fails the test if nothing is relayed within the deadline.
func runRelayForwardCfg(t *testing.T, req *dhcpv4.DHCPv4,
	cfg *config.DHCPRelayConfig) *dhcpv4.DHCPv4 {
	t.Helper()
	client := newFakeConn()
	client.pending = [][]byte{req.ToBytes()}
	server := newFakeConn()
	factory, _ := recordingFactory(client, server)
	m := testManager(factory)
	m.Apply(context.Background(), cfg)
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
//
// #5414: preservation now requires the interface to be a TRUSTED relay uplink
// (`overrides trust-option-82`, RFC 3046 §2.1). On the default UNTRUSTED
// interface a nonzero giaddr is treated as client-forged and overwritten — that
// is asserted separately by TestRunRelay_UntrustedForgedGiaddrOverwritten. This
// test therefore drives the preserve path with a trusted config.
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

	relayed := runRelayForwardCfg(t, req, trustedSingleInterfaceConfig())

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

// trustedSingleInterfaceConfig is singleInterfaceConfig with the group marked
// as a TRUSTED relay uplink (`overrides trust-option-82`, #5414). A nonzero
// inbound giaddr + Option 82 is then treated as an upstream relay's stamp and
// preserved (the RFC 1542 §4.1 intermediate-relay behavior), instead of being
// overwritten as client-forged.
func trustedSingleInterfaceConfig() *config.DHCPRelayConfig {
	return &config.DHCPRelayConfig{
		ServerGroups: map[string]*config.DHCPRelayServerGroup{
			"sg": {Name: "sg", Servers: []string{"192.0.2.1"}},
		},
		Groups: map[string]*config.DHCPRelayGroup{
			"g": {
				Name:              "g",
				Interfaces:        []string{"ge-0-0-0"},
				ActiveServerGroup: "sg",
				TrustOption82:     true,
			},
		},
	}
}

// TestRunRelay_UntrustedForgedGiaddrOverwritten is the #5414 RED-on-revert
// proof for the RFC 3046 §2.1 anti-spoofing fix. A host on the relay's CLIENT
// segment forges a nonzero giaddr (203.0.113.9) and a crafted Option 82 to
// impersonate a downstream relay. On the DEFAULT (untrusted, no
// trust-option-82) interface the relay MUST NOT trust that giaddr: it overwrites
// it with its own address (10.0.0.254) and re-stamps Option 82 with its own
// circuit-id, and it counts the event.
//
// Reverting the fix (making `chained` trust any nonzero giaddr regardless of
// trust-option-82) makes the relay PRESERVE the forged giaddr + Option 82, so
// every assertion below goes RED.
func TestRunRelay_UntrustedForgedGiaddrOverwritten(t *testing.T) {
	const forgedGiaddr = "203.0.113.9"
	forged82 := downstreamOption82("attacker-ckt", "deadbeefcafe")

	req, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	req.OpCode = dhcpv4.OpcodeBootRequest
	req.ClientHWAddr = net.HardwareAddr{0x02, 0, 0, 0, 0, 9}
	req.HopCount = 0
	req.GatewayIPAddr = net.ParseIP(forgedGiaddr) // client forges a relay giaddr
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))
	req.UpdateOption(dhcpv4.OptGeneric(option82, forged82)) // client forges Option 82

	// Default single-interface config = UNTRUSTED client-facing interface.
	relayed := runRelayForwardCfg(t, req, singleInterfaceConfig())

	// giaddr overwritten with THIS relay's own address, NOT the forged value.
	if !relayed.GatewayIPAddr.Equal(net.IPv4(10, 0, 0, 254)) {
		t.Errorf("untrusted giaddr = %v, want 10.0.0.254 (relay overwrites a "+
			"client-forged giaddr); if this is %s the relay trusted the forged "+
			"giaddr (#5414 regression / RFC 3046 §2.1 anti-spoofing bypass)",
			relayed.GatewayIPAddr, forgedGiaddr)
	}

	// Option 82 replaced with the relay's own circuit-id (sub-option 1 ==
	// interface name), NOT the forged remote-id/circuit-id.
	got := relayed.Options.Get(option82)
	if bytes.Equal(got, forged82) {
		t.Errorf("untrusted Option 82 preserved forged value %v — the relay must "+
			"strip+replace a client-forged Option 82 (#5414 regression)", got)
	}
	if len(got) < 2 || got[0] != suboption1CircuitID {
		t.Fatalf("untrusted Option 82 = %v, want relay's own sub-option 1 "+
			"circuit-id", got)
	}
	if circuitID := string(got[2:]); circuitID != "ge-0-0-0" {
		t.Errorf("untrusted circuit-id = %q, want %q (relay's interface name)",
			circuitID, "ge-0-0-0")
	}
	// The anti-spoofing reset is also counted for observability — asserted in
	// TestRunRelay_UntrustedForgedGiaddrResetCounted, which owns the manager.
}

// TestRunRelay_UntrustedForgedGiaddrResetCounted asserts the #5414 observability
// counter: a client-forged nonzero giaddr on an untrusted interface increments
// RequestsUntrustedGiaddrReset. It owns the manager so it can read Stats() after
// the relay processes the datagram.
func TestRunRelay_UntrustedForgedGiaddrResetCounted(t *testing.T) {
	req, err := dhcpv4.New()
	if err != nil {
		t.Fatalf("dhcpv4.New: %v", err)
	}
	req.OpCode = dhcpv4.OpcodeBootRequest
	req.ClientHWAddr = net.HardwareAddr{0x02, 0, 0, 0, 0, 10}
	req.HopCount = 0
	req.GatewayIPAddr = net.ParseIP("203.0.113.9")
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))
	req.UpdateOption(dhcpv4.OptGeneric(option82,
		downstreamOption82("attacker-ckt", "deadbeef")))

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
		t.Fatal("forged-giaddr request was not relayed within 2s")
	}

	var reset uint64
	for _, s := range m.Stats() {
		reset += s.RequestsUntrustedGiaddrReset
	}
	if reset == 0 {
		t.Error("client-forged giaddr overwritten but RequestsUntrustedGiaddrReset " +
			"stayed 0 (#5414 counter regression)")
	}
}
