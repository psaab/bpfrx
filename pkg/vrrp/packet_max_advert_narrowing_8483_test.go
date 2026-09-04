package vrrp

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestConfiguredAdvertiseIntervalOnTheWire8483 pins the arithmetic that the
// #8483 commit gate's bound is DERIVED from, so the bound is a measured
// consequence rather than a sentence in a doc comment.
//
// The chain a configured `advertise-interval <seconds>` takes to the wire:
//
//	seconds  --vrrp.go-->  milliseconds (x1000)
//	         --instance_send.go-->  uint16(ms / 10) centiseconds
//	         --packet.go Marshal-->  MaxAdvertInt & 0x0FFF
//
// The last step is a 12-bit field (RFC 5798 §5.2.7). Everything above 4095
// centiseconds aliases, and the aliasing is silent: nothing on either side
// reports it. 40 s is therefore the last whole-second value that survives, and
// that is exactly the upper bound validateVRRPGroupTimersStrict enforces.
func TestConfiguredAdvertiseIntervalOnTheWire8483(t *testing.T) {
	// The two narrowings the runtime applies, in order, to a configured value.
	//
	// This reads the MARSHALLED BYTES directly rather than round-tripping
	// through ParseVRRPPacket. The parse side masks with 0x0FFF too
	// (packet.go:139), so a Marshal->Parse round-trip is masked TWICE and
	// cannot tell which side did it: widening Marshal's mask to 0xFFFF leaves
	// a round-trip assertion GREEN. That mutation escaped the first version of
	// this cell, which is why the bytes are read here.
	onTheWire := func(t *testing.T, configSeconds int) int {
		t.Helper()
		ms := configSeconds * 1000
		pkt := &VRRPPacket{
			VRID:         1,
			Priority:     100,
			MaxAdvertInt: uint16(ms / 10), // instance_send.go
			IPAddresses:  []net.IP{net.ParseIP("10.0.1.100")},
		}
		wire, err := pkt.Marshal(false, net.ParseIP("10.0.1.1"), net.ParseIP("224.0.0.18"))
		if err != nil {
			t.Fatalf("marshal %d s: %v", configSeconds, err)
		}
		raw := binary.BigEndian.Uint16(wire[4:6])
		// RFC 5798 §5.2.7: the top 4 bits of this word are reserved and MUST
		// be zero on transmit. That is the structural half of the same claim.
		if raw&0xF000 != 0 {
			t.Errorf("advertise-interval %d s: reserved top 4 bits set in the "+
				"transmitted Max Advert Int word (0x%04x)", configSeconds, raw)
		}
		return int(raw)
	}

	// The receive side truncates independently, so a frame from a peer that
	// does NOT mask is still read as 12 bits here. Asserted separately because
	// it is a different guarantee from the transmit one above.
	t.Run("the receive side truncates independently", func(t *testing.T) {
		src, dst := net.ParseIP("10.0.1.1").To4(), net.ParseIP("224.0.0.18").To4()
		pkt := &VRRPPacket{
			VRID: 1, Priority: 100, MaxAdvertInt: 4000,
			IPAddresses: []net.IP{net.ParseIP("10.0.1.100")},
		}
		wire, err := pkt.Marshal(false, src, dst)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		// Forge a non-conforming frame: set the reserved bits a conforming
		// sender would never set, then REPAIR the checksum. Without the repair
		// ParseVRRPPacket rejects the frame and the assertion below never runs
		// — the first version of this subtest did exactly that and a mutation
		// widening the receive mask escaped it.
		wire[4] |= 0xF0
		binary.BigEndian.PutUint16(wire[6:8], 0)
		binary.BigEndian.PutUint16(wire[6:8], vrrpIPv4Checksum(src, dst, wire))

		got, err := ParseVRRPPacket(wire, false, src, dst)
		if err != nil {
			t.Fatalf("control failed: the forged frame must PARSE, or the "+
				"assertion below proves nothing: %v", err)
		}
		if got.MaxAdvertInt != 4000 {
			t.Errorf("receive side must mask the reserved bits: got %d cs, want 4000",
				got.MaxAdvertInt)
		}
	})

	rows := []struct {
		configSeconds int
		wantCentisec  int
		note          string
	}{
		{1, 100, "the default"},
		{40, 4000, "the last whole-second value that encodes — the gate's upper bound"},
		{41, 4, "the first value past the 12-bit field: 4100 cs aliases to 4 cs"},
		{256, 1024, "the issue's value: 256 s advertises as 10.24 s"},
	}

	for _, r := range rows {
		got := onTheWire(t, r.configSeconds)
		if got != r.wantCentisec {
			t.Errorf("advertise-interval %d s: wire Max Advert Int = %d cs, want %d cs (%s)",
				r.configSeconds, got, r.wantCentisec, r.note)
		}
	}

	// The property the table exists to state, asserted directly so it survives
	// a later edit to the rows: the gate's upper bound is the LAST value that
	// round-trips, and the first value past it does not.
	if onTheWire(t, MaxEncodableAdvertiseIntervalSeconds8483)*10 !=
		MaxEncodableAdvertiseIntervalSeconds8483*1000 {
		t.Errorf("%d s must round-trip exactly",
			MaxEncodableAdvertiseIntervalSeconds8483)
	}
	if onTheWire(t, MaxEncodableAdvertiseIntervalSeconds8483+1)*10 ==
		(MaxEncodableAdvertiseIntervalSeconds8483+1)*1000 {
		t.Errorf("%d s must NOT round-trip — if it does, the 12-bit mask is "+
			"gone and the config-layer bound of %d is now wrong",
			MaxEncodableAdvertiseIntervalSeconds8483+1,
			MaxEncodableAdvertiseIntervalSeconds8483)
	}
}

// MaxEncodableAdvertiseIntervalSeconds8483 is the wire-derived value that
// config.MaxVRRPAdvertiseInterval must equal. It lives here, next to the
// arithmetic that produces it, rather than being imported from pkg/config —
// pkg/vrrp is below pkg/config and pinning the literal on the config side
// would encode which spelling is trusted. config's own
// TestAdvertiseIntervalBoundMatchesTheWire8483 asserts the two AGREE.
const MaxEncodableAdvertiseIntervalSeconds8483 = 40
