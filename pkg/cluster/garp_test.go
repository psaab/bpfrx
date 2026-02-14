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
