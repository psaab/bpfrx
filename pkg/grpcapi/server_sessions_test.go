package grpcapi

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/psaab/bpfrx/pkg/dataplane"
)

func TestSessionEntryV4PreservesBothNatLegs(t *testing.T) {
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{198, 51, 100, 10},
		DstIP:    [4]byte{172, 16, 80, 8},
		SrcPort:  hostToNetwork16(54321),
		DstPort:  hostToNetwork16(443),
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		Flags:      dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
		NATSrcIP:   binary.NativeEndian.Uint32([]byte{10, 0, 61, 1}),
		NATDstIP:   binary.NativeEndian.Uint32([]byte{10, 0, 61, 102}),
		NATSrcPort: hostToNetwork16(54321),
		NATDstPort: hostToNetwork16(8443),
	}
	se := sessionEntryV4(
		key,
		val,
		0,
		map[uint16]string{},
		map[uint32]string{},
		map[uint16]string{},
		map[sessionEgressKey]string{},
		true,
	)
	if se.Nat != "SNAT 10.0.61.1:54321; DNAT 10.0.61.102:8443" {
		t.Fatalf("Nat = %q", se.Nat)
	}
	if se.NatSrcAddr != "10.0.61.1" || se.NatDstAddr != "10.0.61.102" {
		t.Fatalf("unexpected nat addrs: %+v", se)
	}
	if se.NatSrcPort != 54321 || se.NatDstPort != 8443 {
		t.Fatalf("unexpected nat ports: %+v", se)
	}
}

func TestSessionEntryV6PreservesBothNatLegs(t *testing.T) {
	var src, dst, natSrc, natDst [16]byte
	copy(src[:], net.ParseIP("2001:db8::10").To16())
	copy(dst[:], net.ParseIP("2001:db8:80::8").To16())
	copy(natSrc[:], net.ParseIP("2001:db8:61::1").To16())
	copy(natDst[:], net.ParseIP("2001:db8:61::102").To16())
	key := dataplane.SessionKeyV6{
		SrcIP:    src,
		DstIP:    dst,
		SrcPort:  hostToNetwork16(54321),
		DstPort:  hostToNetwork16(443),
		Protocol: 6,
	}
	val := dataplane.SessionValueV6{
		Flags:      dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
		NATSrcIP:   natSrc,
		NATDstIP:   natDst,
		NATSrcPort: hostToNetwork16(54321),
		NATDstPort: hostToNetwork16(8443),
	}
	se := sessionEntryV6(
		key,
		val,
		0,
		map[uint16]string{},
		map[uint32]string{},
		map[uint16]string{},
		map[sessionEgressKey]string{},
		true,
	)
	if se.Nat != "SNAT [2001:db8:61::1]:54321; DNAT [2001:db8:61::102]:8443" {
		t.Fatalf("Nat = %q", se.Nat)
	}
	if se.NatSrcAddr != "2001:db8:61::1" || se.NatDstAddr != "2001:db8:61::102" {
		t.Fatalf("unexpected nat addrs: %+v", se)
	}
	if se.NatSrcPort != 54321 || se.NatDstPort != 8443 {
		t.Fatalf("unexpected nat ports: %+v", se)
	}
}

func hostToNetwork16(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
