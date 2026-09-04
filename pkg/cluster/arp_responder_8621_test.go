package cluster

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// #8621: the proxy-ARP responder's frame handling and its answer/refuse
// decision. The kernel cannot answer for a pool address inside its own egress
// interface's connected subnet (every arm of arp_process's proxy branch turns
// on rt->dst.dev vs dev), so this responder is what makes the configured
// proxy-arp entries mean anything. See the header of arp_responder_8621.go.

var (
	testOurMAC   = net.HardwareAddr{0x02, 0xbf, 0x72, 0x16, 0x01, 0x00}
	testAskerMAC = net.HardwareAddr{0x10, 0x66, 0x6a, 0x8b, 0x91, 0xa4}
	testPoolIP   = net.IP{172, 16, 80, 7}
	testAskerIP  = net.IP{172, 16, 80, 174}
	testOtherIP  = net.IP{172, 16, 80, 99}
)

// buildRequestFrame constructs a well-formed Ethernet/IPv4 ARP REQUEST asking
// "who has target". Kept as a builder rather than a literal so a test can
// corrupt exactly one field and leave the rest valid — a fixture that is wrong
// in two places cannot attribute the refusal to either.
func buildRequestFrame(senderMAC net.HardwareAddr, senderIP, target net.IP) []byte {
	pkt := make([]byte, arpFrameLen)
	copy(pkt[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(pkt[6:12], senderMAC)
	binary.BigEndian.PutUint16(pkt[12:14], unix.ETH_P_ARP)
	binary.BigEndian.PutUint16(pkt[14:16], arpHTypeEther)
	binary.BigEndian.PutUint16(pkt[16:18], arpPTypeIPv4)
	pkt[18] = arpHLenEther
	pkt[19] = arpPLenIPv4
	binary.BigEndian.PutUint16(pkt[20:22], arpOpcodeReq)
	copy(pkt[22:28], senderMAC)
	copy(pkt[28:32], senderIP.To4())
	copy(pkt[38:42], target.To4())
	return pkt
}

// answerOnly returns a policy that answers for exactly one address, so a test
// can tell "the policy was consulted" from "the responder answers everything".
func answerOnly(ip net.IP) ARPAnswerPolicy {
	return func(_ string, target net.IP) bool { return target.Equal(ip) }
}

// The whole point: a request for a proxied pool address is answered, and the
// reply is a correct UNICAST reply back to the asker.
//
// The byte-level assertions matter. A reply with the right shape but the wrong
// sender MAC teaches the asker to send pool traffic to the wrong node — which
// on a cluster is #8405's misdelivery, not a cosmetic error — and a broadcast
// reply programs the mapping into every neighbour instead of the one that
// asked.
func TestAProxiedPoolAddressIsAnsweredWithAUnicastReply8621(t *testing.T) {
	frame := buildRequestFrame(testAskerMAC, testAskerIP, testPoolIP)
	reply, _, verdict := HandleARPFrame(frame, testOurMAC, "ge-0-0-2.80", answerOnly(testPoolIP))
	if verdict != ARPReplyAnswer {
		t.Fatalf("verdict = %v, want ARPReplyAnswer — the responder declined the very "+
			"case it exists for", verdict)
	}
	if len(reply) != arpFrameLen {
		t.Fatalf("reply length %d, want %d", len(reply), arpFrameLen)
	}
	if got := net.HardwareAddr(reply[0:6]).String(); got != testAskerMAC.String() {
		t.Errorf("ethernet dst = %s, want the asker %s: a broadcast reply programs "+
			"every neighbour on the segment, which is the announce path's job and "+
			"has its own RG gate", got, testAskerMAC)
	}
	if got := net.HardwareAddr(reply[6:12]).String(); got != testOurMAC.String() {
		t.Errorf("ethernet src = %s, want our MAC %s", got, testOurMAC)
	}
	if op := binary.BigEndian.Uint16(reply[20:22]); op != arpOpcodeReply {
		t.Errorf("opcode = %d, want %d (reply)", op, arpOpcodeReply)
	}
	if got := net.HardwareAddr(reply[22:28]).String(); got != testOurMAC.String() {
		t.Errorf("sender hardware = %s, want our MAC %s — this is the value the "+
			"asker caches, so a wrong one sends pool traffic to the wrong node",
			got, testOurMAC)
	}
	if got := net.IP(reply[28:32]); !got.Equal(testPoolIP) {
		t.Errorf("sender protocol = %s, want the pool address %s", got, testPoolIP)
	}
	if got := net.IP(reply[38:42]); !got.Equal(testAskerIP) {
		t.Errorf("target protocol = %s, want the asker %s", got, testAskerIP)
	}
}

// THE CONTROL that makes the cell above mean something. Same frame shape, an
// address this node does not proxy: it must NOT be answered. Without this, a
// responder that answers every ARP request on the segment passes the test
// above — and that responder is `proxy_arp_pvlan`, the option this design
// exists to avoid.
func TestAnUnproxiedAddressIsNotAnswered8621(t *testing.T) {
	frame := buildRequestFrame(testAskerMAC, testAskerIP, testOtherIP)
	reply, _, verdict := HandleARPFrame(frame, testOurMAC, "ge-0-0-2.80", answerOnly(testPoolIP))
	if reply != nil || verdict != ARPReplyNotOurs {
		t.Fatalf("answered for %s, which this node does not proxy (verdict %v). A "+
			"responder that answers everything on the segment is exactly the "+
			"unbounded behaviour proxy_arp_pvlan was refused for", testOtherIP, verdict)
	}
}

// Each structural refusal, bound separately so a mutation that removes one is
// attributable. The policy says YES to everything here on purpose: these
// refusals must hold even when the address IS one we proxy.
func TestTheStructuralRefusalsHoldEvenForAProxiedAddress8621(t *testing.T) {
	yes := func(_ string, _ net.IP) bool { return true }

	t.Run("our own frame", func(t *testing.T) {
		// Our gratuitous announces come back on this socket. Answering them
		// would be a self-sustaining loop.
		frame := buildRequestFrame(testOurMAC, testAskerIP, testPoolIP)
		if reply, _, v := HandleARPFrame(frame, testOurMAC, "if", yes); reply != nil || v != ARPReplyOwnFrame {
			t.Fatalf("verdict %v, want ARPReplyOwnFrame", v)
		}
	})

	t.Run("gratuitous / self probe", func(t *testing.T) {
		frame := buildRequestFrame(testAskerMAC, testPoolIP, testPoolIP)
		if reply, _, v := HandleARPFrame(frame, testOurMAC, "if", yes); reply != nil || v != ARPReplyGratuitous {
			t.Fatalf("verdict %v, want ARPReplyGratuitous", v)
		}
	})

	t.Run("an ARP REPLY is not a question", func(t *testing.T) {
		frame := buildRequestFrame(testAskerMAC, testAskerIP, testPoolIP)
		binary.BigEndian.PutUint16(frame[20:22], arpOpcodeReply)
		if reply, _, _ := HandleARPFrame(frame, testOurMAC, "if", yes); reply != nil {
			t.Fatal("answered an ARP reply as though it were a request")
		}
	})

	t.Run("short frame", func(t *testing.T) {
		frame := buildRequestFrame(testAskerMAC, testAskerIP, testPoolIP)[:30]
		if reply, _, _ := HandleARPFrame(frame, testOurMAC, "if", yes); reply != nil {
			t.Fatal("answered a truncated frame")
		}
	})

	t.Run("nil policy answers nothing", func(t *testing.T) {
		frame := buildRequestFrame(testAskerMAC, testAskerIP, testPoolIP)
		if reply, _, v := HandleARPFrame(frame, testOurMAC, "if", nil); reply != nil || v != ARPReplyNotOurs {
			t.Fatalf("verdict %v with a nil policy, want ARPReplyNotOurs", v)
		}
	})
}

// The #2369 fail-closed, transplanted. The sender hardware/protocol addresses
// live at offsets that are only correct for Ethernet/IPv4 ARP. A frame
// declaring a different hardware or protocol type, or different lengths, would
// otherwise have attacker-chosen bytes read as a MAC and an IP — and this
// responder turns what it reads into a frame it sends.
//
// Each row corrupts exactly ONE header field and leaves the rest valid, so the
// refusal is attributable to that field. The final row is the positive control:
// the uncorrupted frame from the same builder IS answered, so a refusal above
// cannot be blamed on the fixture.
func TestAMalformedARPHeaderIsRefusedBeforeItsAddressesAreRead8621(t *testing.T) {
	yes := func(_ string, _ net.IP) bool { return true }
	for _, tc := range []struct {
		name    string
		corrupt func([]byte)
	}{
		{"hardware type not ethernet", func(f []byte) { binary.BigEndian.PutUint16(f[14:16], 6) }},
		{"protocol type not ipv4", func(f []byte) { binary.BigEndian.PutUint16(f[16:18], 0x86dd) }},
		{"hardware length not 6", func(f []byte) { f[18] = 8 }},
		{"protocol length not 4", func(f []byte) { f[19] = 16 }},
		{"ethertype not arp", func(f []byte) { binary.BigEndian.PutUint16(f[12:14], 0x0800) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := buildRequestFrame(testAskerMAC, testAskerIP, testPoolIP)
			tc.corrupt(frame)
			if reply, _, _ := HandleARPFrame(frame, testOurMAC, "if", yes); reply != nil {
				t.Fatalf("answered a frame with %s — the addresses this responder "+
					"copies into its reply were read at offsets that are only "+
					"correct for ethernet/ipv4 ARP", tc.name)
			}
		})
	}

	// POSITIVE CONTROL on the same builder.
	frame := buildRequestFrame(testAskerMAC, testAskerIP, testPoolIP)
	if reply, _, v := HandleARPFrame(frame, testOurMAC, "if", yes); reply == nil {
		t.Fatalf("the UNCORRUPTED frame from this builder was refused (%v), so every "+
			"refusal above may be the fixture rather than the guard", v)
	}
}
