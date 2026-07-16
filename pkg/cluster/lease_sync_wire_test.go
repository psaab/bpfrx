package cluster

import (
	"encoding/binary"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// TestDHCPLeaseEncode_OversizedFieldFailsClosed is the #4892 regression. The
// lease-sync wire prefixes each string with a uint16 length; a field longer than
// math.MaxUint16 (65535) bytes would silently narrow the prefix (uint16(len)
// wraps) and the peer would misframe the record — reading the wrapped low-16
// length and then the string's trailing bytes as later fields, corrupting the
// lease identity/type/prefix-length/hostname on the standby.
//
// The fix bounds the writer: encodeOneLease REJECTS an oversized lease (returns
// an error) rather than emitting a misframed record, and encodeDHCPLeasePayload
// DROPS it from the push (count stays consistent) so the surviving leases still
// round-trip byte-identical.
//
// FAIL-ON-REVERT: restoring `uint16(len(s))` narrowing in putLeaseString removes
// the error, so (1) encodeOneLease returns nil error on the oversized lease and
// this test's err==nil check fails, and (2) the oversized record is emitted
// misframed, so the payload decodes 3 leases (the middle one corrupted) instead
// of the 2 clean survivors — both assertions go RED.
func TestDHCPLeaseEncode_OversizedFieldFailsClosed(t *testing.T) {
	oversize := math.MaxUint16 + 1 // 65536: first length that overflows the uint16 prefix.

	// Each variable-length field must independently fail closed — the error is
	// threaded at every putLeaseString site in encodeOneLease.
	cases := []struct {
		field string
		set   func(*dhcpserver.SyncLease)
	}{
		{"Address", func(l *dhcpserver.SyncLease) { l.Address = strings.Repeat("a", oversize) }},
		{"HWAddress", func(l *dhcpserver.SyncLease) { l.HWAddress = strings.Repeat("b", oversize) }},
		{"ClientID", func(l *dhcpserver.SyncLease) { l.ClientID = strings.Repeat("c", oversize) }},
		{"DUID", func(l *dhcpserver.SyncLease) { l.DUID = strings.Repeat("d", oversize) }},
		{"LeaseType", func(l *dhcpserver.SyncLease) { l.LeaseType = strings.Repeat("e", oversize) }},
		{"Hostname", func(l *dhcpserver.SyncLease) { l.Hostname = strings.Repeat("f", oversize) }},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			l := dhcpserver.SyncLease{Family: 4, Address: "10.0.0.1", SubnetID: 1}
			tc.set(&l)
			if _, err := encodeOneLease(l); err == nil {
				t.Fatalf("encodeOneLease with an oversized %s did not fail closed; "+
					"the uint16 prefix silently narrowed and the record is misframed", tc.field)
			}
		})
	}

	// Boundary: exactly math.MaxUint16 bytes still fits the prefix and must encode.
	atLimit := dhcpserver.SyncLease{Family: 4, Address: "10.0.0.2", SubnetID: 1,
		Hostname: strings.Repeat("h", math.MaxUint16)}
	if _, err := encodeOneLease(atLimit); err != nil {
		t.Fatalf("encodeOneLease rejected a field of exactly %d bytes (must fit the uint16 prefix): %v",
			math.MaxUint16, err)
	}

	// Payload-level: an oversized lease is DROPPED, the clean leases survive
	// byte-identical, and the count reflects only what was emitted.
	normal1 := dhcpserver.SyncLease{
		Family: 4, Address: "10.0.61.7", SubnetID: 1,
		HWAddress: "aa:bb:cc:dd:ee:07", ClientID: "01:aa:bb:cc:dd:ee:07",
		ValidLife: 3600, Remaining: 3000, Hostname: "host-1", FQDNFwd: true,
	}
	oversized := dhcpserver.SyncLease{
		Family: 6, Address: "2001:db8::dead", SubnetID: 2,
		DUID: "00:01:00:03", IAID: 9, LeaseType: "IA_NA",
		ValidLife: 7200, Remaining: 6000, Hostname: strings.Repeat("x", oversize),
	}
	normal2 := dhcpserver.SyncLease{
		Family: 6, Address: "2001:db8::beef", SubnetID: 2,
		DUID: "00:01:00:04", IAID: 11, LeaseType: "IA_PD", PrefixLen: 56,
		ValidLife: 7200, Remaining: 6000, Hostname: "host-2", FQDNRev: true,
	}
	payload := encodeDHCPLeasePayload([]dhcpserver.SyncLease{normal1, oversized, normal2})
	out := decodeDHCPLeasePayload(payload)
	if len(out) != 2 {
		t.Fatalf("payload decoded %d leases, want 2 (the oversized lease must be dropped, "+
			"not emitted misframed): %+v", len(out), out)
	}
	if !reflect.DeepEqual(out[0], normal1) {
		t.Errorf("first surviving lease not byte-identical:\n got=%+v\nwant=%+v", out[0], normal1)
	}
	if !reflect.DeepEqual(out[1], normal2) {
		t.Errorf("second surviving lease not byte-identical (a misframed oversized record "+
			"would surface here):\n got=%+v\nwant=%+v", out[1], normal2)
	}
}

// Test: the #2239 DHCP-lease wire codec round-trips a mixed v4/v6 set,
// including a PD lease and the FQDN flags.
func TestDHCPLeasePayload_RoundTrip(t *testing.T) {
	in := []dhcpserver.SyncLease{
		{
			Family: 4, Address: "10.0.61.50", SubnetID: 1,
			HWAddress: "aa:bb:cc:dd:ee:01", ClientID: "01:aa:bb:cc:dd:ee:01",
			ValidLife: 3600, Remaining: 3000, State: 0,
			Hostname: "host-a", FQDNFwd: true,
		},
		{
			Family: 6, Address: "2001:db8::100", SubnetID: 2,
			DUID: "00:01:00:01", IAID: 42, LeaseType: "IA_NA",
			ValidLife: 7200, Remaining: 6000, State: 0,
			Hostname: "host-b", FQDNRev: true,
		},
		{
			Family: 6, Address: "2001:db8:abcd::", SubnetID: 2,
			DUID: "00:01:00:02", IAID: 7, LeaseType: "IA_PD", PrefixLen: 56,
			ValidLife: 7200, Remaining: 6000, State: 0,
		},
	}
	payload := encodeDHCPLeasePayload(in)
	out := decodeDHCPLeasePayload(payload)
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

// Test: an empty set encodes as a 4-byte zero count and decodes to empty (a
// legitimate "I serve no leases" push, distinct from a legacy peer).
func TestDHCPLeasePayload_Empty(t *testing.T) {
	payload := encodeDHCPLeasePayload(nil)
	if len(payload) != 4 {
		t.Fatalf("empty payload len = %d, want 4", len(payload))
	}
	out := decodeDHCPLeasePayload(payload)
	if len(out) != 0 {
		t.Fatalf("decoded empty payload to %d leases", len(out))
	}
}

// Test: length-gated trailing-field tolerance. A "newer peer" record with extra
// trailing bytes after the known fields must decode the known fields and ignore
// the extra (forward compat); a "legacy peer" record truncated before the
// trailing fields must decode the leading fields and zero the rest.
func TestDHCPLeasePayload_LengthGated(t *testing.T) {
	l := dhcpserver.SyncLease{
		Family: 4, Address: "10.0.61.9", SubnetID: 1,
		HWAddress: "aa", ValidLife: 100, Remaining: 50, State: 0,
		Hostname: "h", FQDNFwd: true,
	}
	rec, err := encodeOneLease(l)
	if err != nil {
		t.Fatalf("encodeOneLease: %v", err)
	}

	// Newer peer: append 8 bytes of an unknown future field.
	newer := append(append([]byte{}, rec...), 1, 2, 3, 4, 5, 6, 7, 8)
	got := decodeOneLease(newer)
	if got.Address != l.Address || got.Hostname != l.Hostname || !got.FQDNFwd {
		t.Errorf("newer-peer record lost known fields: %+v", got)
	}

	// Legacy peer: truncate the record so the trailing flags byte (and
	// hostname) are missing. The decoder must not panic and must zero the
	// absent fields rather than mis-read.
	short := rec[:len(rec)-3]
	got2 := decodeOneLease(short)
	if got2.Address != l.Address {
		t.Errorf("legacy-peer record lost leading field address: %+v", got2)
	}
	// FQDNFwd was the last byte; truncated → must be false (zero).
	if got2.FQDNFwd {
		t.Errorf("legacy-peer truncated record must not set absent flag")
	}
}

// Test: a truncated full-set payload (a record cut mid-stream) decodes the
// records that fully arrived rather than erroring the whole push.
func TestDHCPLeasePayload_TruncatedStream(t *testing.T) {
	in := []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.0.1", SubnetID: 1, Remaining: 10},
		{Family: 4, Address: "10.0.0.2", SubnetID: 1, Remaining: 10},
	}
	payload := encodeDHCPLeasePayload(in)
	// Lie about the count to 5 but only ship the real 2 records: the decoder
	// must stop at the end of the buffer, returning the 2 complete records.
	binary.LittleEndian.PutUint32(payload[:4], 5)
	out := decodeDHCPLeasePayload(payload)
	if len(out) != 2 {
		t.Fatalf("over-counted truncated stream decoded %d, want 2", len(out))
	}
}

// Test: the new sync message types do not collide and are above the legacy set
// (back-compat: a legacy peer hits the default case and ignores them).
func TestDHCPLeaseMsgTypes(t *testing.T) {
	if syncMsgDHCPLeaseV4 != 25 || syncMsgDHCPLeaseV6 != 26 {
		t.Fatalf("unexpected DHCP lease msg types: v4=%d v6=%d", syncMsgDHCPLeaseV4, syncMsgDHCPLeaseV6)
	}
	if syncMsgDHCPLeaseV4 <= syncMsgHeartbeatAck {
		t.Fatalf("DHCP lease types must be above the legacy set")
	}
}

// Test: storePeerDHCPLeases + the accessors hold the standby's peer set per
// family and return copies (mutating the returned slice does not corrupt the
// store).
func TestPeerDHCPLeasesHold(t *testing.T) {
	s := &SessionSync{}
	v4 := []dhcpserver.SyncLease{{Family: 4, Address: "10.0.0.5", Remaining: 100}}
	v6 := []dhcpserver.SyncLease{{Family: 6, Address: "2001:db8::5", Remaining: 200}}
	s.storePeerDHCPLeases(4, v4)
	s.storePeerDHCPLeases(6, v6)

	got4 := s.PeerDHCPLeases4()
	got6 := s.PeerDHCPLeases6()
	if len(got4) != 1 || got4[0].Address != "10.0.0.5" {
		t.Errorf("v4 hold wrong: %+v", got4)
	}
	if len(got6) != 1 || got6[0].Address != "2001:db8::5" {
		t.Errorf("v6 hold wrong: %+v", got6)
	}
	// Mutating the copy must not affect the store.
	got4[0].Address = "mutated"
	if s.PeerDHCPLeases4()[0].Address != "10.0.0.5" {
		t.Errorf("accessor did not return a copy")
	}

	// A full-set replace (push semantics) overwrites.
	s.storePeerDHCPLeases(4, nil)
	if len(s.PeerDHCPLeases4()) != 0 {
		t.Errorf("full-set replace did not clear v4")
	}
}

// TestPeerDHCPLeasesAged is the #4871 regression guard. SyncLease.Remaining is
// seconds-of-lifetime-left at the SENDER's read time with no sample epoch, so a
// set held on the standby must be AGED by the receiver's residence before it is
// seeded on takeover — otherwise a held lease is re-anchored to
// now_local+Remaining and resurrected past its true expiry (duplicate
// allocation). A lease that has aged to zero must be DROPPED, not floored to 1.
//
// Fail-on-revert: reverting peerDHCPLeasesAged to a plain copy makes both
// assertions fail — the still-valid lease keeps its full 600 (not 500) and the
// expired lease is returned instead of dropped.
func TestPeerDHCPLeasesAged(t *testing.T) {
	s := &SessionSync{}
	now := time.Unix(1_700_000_000, 0)
	// Received 100s ago.
	recvAt := now.Add(-100 * time.Second)
	s.peerDHCPLeases4 = []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.0.5", Remaining: 600}, // -> 500 after aging
		{Family: 4, Address: "10.0.0.6", Remaining: 60},  // -> dropped (60-100<=0)
	}
	s.peerDHCPLeases4RecvAt = recvAt

	got := s.peerDHCPLeasesAged(4, now)
	if len(got) != 1 {
		t.Fatalf("aged set: got %d leases, want 1 (the expired one must be dropped): %+v", len(got), got)
	}
	if got[0].Address != "10.0.0.5" {
		t.Fatalf("wrong lease survived: %+v", got[0])
	}
	if got[0].Remaining != 500 {
		t.Errorf("aged Remaining = %d, want 500 (600 - 100s residence)", got[0].Remaining)
	}
	// The held set itself must be untouched (aging works on copies).
	s.peerDHCPLeasesMu.Lock()
	held := s.peerDHCPLeases4[0].Remaining
	s.peerDHCPLeasesMu.Unlock()
	if held != 600 {
		t.Errorf("aging mutated the held set: Remaining = %d, want 600", held)
	}
}

// Test (#2239 review): a frame claiming an absurd record count must not
// over-allocate. Pre-fix decodeDHCPLeasePayload did make([]SyncLease, 0,
// count) with the untrusted on-wire count, so a frame claiming
// count=0xFFFFFFFF (~160 bytes/record => hundreds of GB) panicked in
// makeslice before the loop's truncation guard fired. The clamp bounds the
// preallocation to len(payload)/4; decoding a huge-count empty-body frame
// returns zero leases without panicking.
func TestDHCPLeasePayload_HugeCountDoesNotOverAllocate(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("decodeDHCPLeasePayload panicked on a huge on-wire count (preallocation not clamped): %v", r)
		}
	}()
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint32(payload, 0xFFFFFFFF)
	out := decodeDHCPLeasePayload(payload)
	if len(out) != 0 {
		t.Errorf("huge-count empty-body frame: got %d leases, want 0", len(out))
	}
}
