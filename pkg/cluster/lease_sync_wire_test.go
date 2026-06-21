package cluster

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

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
	rec := encodeOneLease(l)

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
