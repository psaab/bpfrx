package cluster

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBuildGratuitousARP(t *testing.T) {
	mac, _ := net.ParseMAC("de:ad:be:ef:00:01")
	ip := net.ParseIP("10.0.1.10").To4()

	pkt := buildGratuitousARP(mac, ip)

	if len(pkt) != 42 {
		t.Fatalf("packet length = %d, want 42", len(pkt))
	}

	// Ethernet destination: broadcast.
	for i := 0; i < 6; i++ {
		if pkt[i] != 0xff {
			t.Errorf("dst MAC[%d] = 0x%02x, want 0xff", i, pkt[i])
		}
	}

	// Ethernet source: our MAC.
	for i := 0; i < 6; i++ {
		if pkt[6+i] != mac[i] {
			t.Errorf("src MAC[%d] = 0x%02x, want 0x%02x", i, pkt[6+i], mac[i])
		}
	}

	// EtherType: ARP.
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	if etherType != unix.ETH_P_ARP {
		t.Errorf("ethertype = 0x%04x, want 0x%04x", etherType, unix.ETH_P_ARP)
	}

	// ARP hardware type: Ethernet (1).
	hwType := binary.BigEndian.Uint16(pkt[14:16])
	if hwType != 1 {
		t.Errorf("hardware type = %d, want 1", hwType)
	}

	// ARP protocol type: IPv4.
	protoType := binary.BigEndian.Uint16(pkt[16:18])
	if protoType != 0x0800 {
		t.Errorf("protocol type = 0x%04x, want 0x0800", protoType)
	}

	// Hardware/protocol address lengths.
	if pkt[18] != 6 {
		t.Errorf("hw addr len = %d, want 6", pkt[18])
	}
	if pkt[19] != 4 {
		t.Errorf("proto addr len = %d, want 4", pkt[19])
	}

	// Opcode: ARP reply (2).
	opcode := binary.BigEndian.Uint16(pkt[20:22])
	if opcode != 2 {
		t.Errorf("opcode = %d, want 2 (reply)", opcode)
	}

	// Sender hardware address = our MAC.
	for i := 0; i < 6; i++ {
		if pkt[22+i] != mac[i] {
			t.Errorf("sender MAC[%d] = 0x%02x, want 0x%02x", i, pkt[22+i], mac[i])
		}
	}

	// Sender protocol address = our IP.
	for i := 0; i < 4; i++ {
		if pkt[28+i] != ip[i] {
			t.Errorf("sender IP[%d] = %d, want %d", i, pkt[28+i], ip[i])
		}
	}

	// Target hardware address: broadcast.
	for i := 0; i < 6; i++ {
		if pkt[32+i] != 0xff {
			t.Errorf("target MAC[%d] = 0x%02x, want 0xff", i, pkt[32+i])
		}
	}

	// Target protocol address = our IP (GARP).
	for i := 0; i < 4; i++ {
		if pkt[38+i] != ip[i] {
			t.Errorf("target IP[%d] = %d, want %d", i, pkt[38+i], ip[i])
		}
	}
}

func TestHtons(t *testing.T) {
	// htons should convert host-endian to network (big-endian).
	result := htons(0x0806)
	// Verify it round-trips: reading it back as big-endian gives 0x0806.
	b := make([]byte, 2)
	binary.NativeEndian.PutUint16(b, result)
	val := binary.BigEndian.Uint16(b)
	if val != 0x0806 {
		t.Errorf("htons(0x0806) round-trip = 0x%04x, want 0x0806", val)
	}
}

func TestSendGratuitousARP_IPv6Rejected(t *testing.T) {
	err := SendGratuitousARP("lo", net.ParseIP("::1"), 1)
	if err == nil {
		t.Error("expected error for IPv6 address")
	}
}

func TestSendGratuitousIPv6_IPv4Rejected(t *testing.T) {
	err := SendGratuitousIPv6("lo", net.ParseIP("10.0.1.1"), 1)
	if err == nil {
		t.Error("expected error for IPv4 address")
	}
}

func TestBuildUnsolicitedNA(t *testing.T) {
	mac, _ := net.ParseMAC("de:ad:be:ef:00:01")
	ip := net.ParseIP("2001:db8::1")

	pkt := buildUnsolicitedNA(mac, ip)

	if len(pkt) != 86 {
		t.Fatalf("packet length = %d, want 86", len(pkt))
	}

	// Ethernet destination: IPv6 all-nodes multicast MAC.
	wantDstMAC := []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
	for i := 0; i < 6; i++ {
		if pkt[i] != wantDstMAC[i] {
			t.Errorf("dst MAC[%d] = 0x%02x, want 0x%02x", i, pkt[i], wantDstMAC[i])
		}
	}

	// Ethernet source: our MAC.
	for i := 0; i < 6; i++ {
		if pkt[6+i] != mac[i] {
			t.Errorf("src MAC[%d] = 0x%02x, want 0x%02x", i, pkt[6+i], mac[i])
		}
	}

	// EtherType: IPv6.
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	if etherType != unix.ETH_P_IPV6 {
		t.Errorf("ethertype = 0x%04x, want 0x%04x", etherType, unix.ETH_P_IPV6)
	}

	// IPv6 version.
	if pkt[14]>>4 != 6 {
		t.Errorf("IPv6 version = %d, want 6", pkt[14]>>4)
	}

	// IPv6 payload length: 32 (24 NA + 8 TLLA option).
	payloadLen := binary.BigEndian.Uint16(pkt[18:20])
	if payloadLen != 32 {
		t.Errorf("payload length = %d, want 32", payloadLen)
	}

	// Next header: ICMPv6 (58).
	if pkt[20] != 58 {
		t.Errorf("next header = %d, want 58 (ICMPv6)", pkt[20])
	}

	// Hop limit: 255.
	if pkt[21] != 255 {
		t.Errorf("hop limit = %d, want 255", pkt[21])
	}

	// Source IP: our IPv6 address.
	srcIP := net.IP(pkt[22:38])
	if !srcIP.Equal(ip) {
		t.Errorf("source IP = %s, want %s", srcIP, ip)
	}

	// Destination: ff02::1.
	dstIP := net.IP(pkt[38:54])
	wantDst := net.ParseIP("ff02::1")
	if !dstIP.Equal(wantDst) {
		t.Errorf("destination IP = %s, want %s", dstIP, wantDst)
	}

	// ICMPv6 type: 136 (Neighbor Advertisement).
	if pkt[54] != 136 {
		t.Errorf("ICMPv6 type = %d, want 136", pkt[54])
	}

	// ICMPv6 code: 0.
	if pkt[55] != 0 {
		t.Errorf("ICMPv6 code = %d, want 0", pkt[55])
	}

	// Flags: Override=1 (0x20).
	if pkt[58] != 0x20 {
		t.Errorf("NA flags = 0x%02x, want 0x20 (Override)", pkt[58])
	}

	// Target address: our IPv6 address.
	targetIP := net.IP(pkt[62:78])
	if !targetIP.Equal(ip) {
		t.Errorf("target IP = %s, want %s", targetIP, ip)
	}

	// TLLA option: type=2, length=1.
	if pkt[78] != 2 {
		t.Errorf("TLLA option type = %d, want 2", pkt[78])
	}
	if pkt[79] != 1 {
		t.Errorf("TLLA option length = %d, want 1", pkt[79])
	}

	// TLLA option: our MAC.
	for i := 0; i < 6; i++ {
		if pkt[80+i] != mac[i] {
			t.Errorf("TLLA MAC[%d] = 0x%02x, want 0x%02x", i, pkt[80+i], mac[i])
		}
	}

	// Verify checksum is non-zero (computed).
	csum := binary.BigEndian.Uint16(pkt[56:58])
	if csum == 0 {
		t.Error("ICMPv6 checksum should be non-zero")
	}
}

func TestICMPv6Checksum(t *testing.T) {
	// Build a known packet and verify checksum validates.
	mac, _ := net.ParseMAC("de:ad:be:ef:00:01")
	ip := net.ParseIP("2001:db8::1")
	pkt := buildUnsolicitedNA(mac, ip)

	// Extract the checksum that was written.
	originalCsum := binary.BigEndian.Uint16(pkt[56:58])

	// Zero the checksum field and recompute.
	pkt[56] = 0
	pkt[57] = 0
	recomputed := icmpv6Checksum(pkt[22:38], pkt[38:54], pkt[54:86])
	if recomputed != originalCsum {
		t.Errorf("recomputed checksum 0x%04x != original 0x%04x", recomputed, originalCsum)
	}
}
