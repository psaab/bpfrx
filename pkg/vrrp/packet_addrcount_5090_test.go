package vrrp

import (
	"net"
	"testing"
)

// #5090: Marshal sizes and fills the advert payload from an unbounded int
// address count but narrows the header Count field with uint8(count). Without a
// bound, 256 addresses serialize a full 8+N-byte payload while Count wraps to 0
// (256 mod 256) — receivers reject or misparse the advert. The guard rejects
// len(IPAddresses) outside 1..255 BEFORE serialization so a wrong Count is never
// emitted. These tests assert the real Marshal result (error vs the serialized
// Count byte), not an internal flag.

// makeV4Addrs builds n distinct IPv4 addresses for advert construction.
func makeV4Addrs(n int) []net.IP {
	addrs := make([]net.IP, 0, n)
	for i := 0; i < n; i++ {
		addrs = append(addrs, net.IPv4(10, 0, byte(i>>8), byte(i)))
	}
	return addrs
}

// TestMarshal_RejectsOver255Addresses is the fail-on-revert gate: 256 addresses
// must return an error and NOT produce a buffer with Count=0. Neutralizing the
// guard (buf[3]=uint8(count) with no bound) makes Marshal succeed and Count wrap
// to 0 — this test then goes RED because err == nil.
func TestMarshal_RejectsOver255Addresses(t *testing.T) {
	src := net.IPv4(10, 0, 0, 2)
	dst := net.IPv4(224, 0, 0, 18)

	pkt := &VRRPPacket{
		VRID:         42,
		Priority:     200,
		MaxAdvertInt: 100,
		IPAddresses:  makeV4Addrs(256),
	}

	buf, err := pkt.Marshal(false, src, dst)
	if err == nil {
		// Under the neutralized (buggy) code Marshal succeeds and the Count byte
		// wraps to 0 despite 256 serialized addresses. Assert that concrete wrong
		// result so the fail-on-revert direction is unambiguous.
		gotCount := buf[3]
		t.Fatalf("expected error for 256 addresses; got nil err with Count byte = %d "+
			"(256 wrapped to 0 → receivers reject the advert)", gotCount)
	}
}

// TestMarshal_AddressCountBoundaries pins that the guard does not off-by-one
// reject a legal maximum (255) and does reject 256, and that a valid count is
// serialized into the Count byte unchanged.
func TestMarshal_AddressCountBoundaries(t *testing.T) {
	src := net.IPv4(10, 0, 0, 2)
	dst := net.IPv4(224, 0, 0, 18)

	cases := []struct {
		count     int
		wantError bool
	}{
		{0, true},    // empty advert is meaningless (Count must be >= 1)
		{1, false},   // minimum legal
		{254, false}, // just below max
		{255, false}, // maximum representable in the u8 Count field
		{256, true},  // wraps to 0 — must be rejected
	}

	for _, tc := range cases {
		pkt := &VRRPPacket{
			VRID:         7,
			Priority:     100,
			MaxAdvertInt: 100,
			IPAddresses:  makeV4Addrs(tc.count),
		}
		buf, err := pkt.Marshal(false, src, dst)
		if tc.wantError {
			if err == nil {
				t.Errorf("count=%d: expected error, got nil (Count byte=%d)", tc.count, buf[3])
			}
			continue
		}
		if err != nil {
			t.Errorf("count=%d: unexpected error: %v", tc.count, err)
			continue
		}
		// The serialized Count byte must equal the address count exactly.
		if int(buf[3]) != tc.count {
			t.Errorf("count=%d: Count byte = %d, want %d", tc.count, buf[3], tc.count)
		}
		// Payload length must match header + count*addrSize (IPv4 = 4 bytes each).
		if wantLen := vrrpHeaderLen + tc.count*4; len(buf) != wantLen {
			t.Errorf("count=%d: buffer len = %d, want %d", tc.count, len(buf), wantLen)
		}
	}
}

// TestMarshal_NormalAdvertUnchanged is the regression guard: a small (1-3
// address) advert must serialize byte-identically to the pre-guard behavior —
// Count == len(addresses) and the payload is untouched. The guard only rejects
// out-of-range counts; it must not alter the normal 1..255 path.
func TestMarshal_NormalAdvertUnchanged(t *testing.T) {
	src := net.IPv4(10, 0, 0, 2)
	dst := net.IPv4(224, 0, 0, 18)

	pkt := &VRRPPacket{
		VRID:         42,
		Priority:     200,
		MaxAdvertInt: 100,
		IPAddresses: []net.IP{
			net.IPv4(10, 0, 1, 1),
			net.IPv4(10, 0, 1, 2),
			net.IPv4(10, 0, 1, 3),
		},
	}

	buf, err := pkt.Marshal(false, src, dst)
	if err != nil {
		t.Fatalf("normal 3-address advert must marshal: %v", err)
	}

	// Header fields must be exactly as before the guard.
	if got := buf[0]; got != (vrrpVersion<<4)|vrrpTypeAdvert {
		t.Errorf("byte0 version|type = 0x%02x, want 0x%02x", got, (vrrpVersion<<4)|vrrpTypeAdvert)
	}
	if buf[1] != 42 {
		t.Errorf("VRID = %d, want 42", buf[1])
	}
	if buf[2] != 200 {
		t.Errorf("Priority = %d, want 200", buf[2])
	}
	if buf[3] != 3 {
		t.Errorf("Count = %d, want 3 (== len(IPAddresses))", buf[3])
	}
	if wantLen := vrrpHeaderLen + 3*4; len(buf) != wantLen {
		t.Fatalf("buffer len = %d, want %d", len(buf), wantLen)
	}

	// The three addresses must be laid out contiguously after the 8-byte header.
	for i, want := range []net.IP{
		net.IPv4(10, 0, 1, 1),
		net.IPv4(10, 0, 1, 2),
		net.IPv4(10, 0, 1, 3),
	} {
		off := vrrpHeaderLen + i*4
		got := net.IP(buf[off : off+4])
		if !got.Equal(want.To4()) {
			t.Errorf("address %d = %v, want %v", i, got, want)
		}
	}
}
