package cluster

import (
	"encoding/binary"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #7175: a truncated-but-framed session-sync record must not decode ok=true
// with its policy/zone/NAT fields left at zero.
//
// WHY ZERO IS NOT "MISSING". A zeroed SessionID, PolicyID, zone pair and NAT
// tuple are not absent values — they are VALUES the standby installs and
// carries, and they become live forwarding state on the next failover.
//
// CORRECTION to the original #7175 rationale: this said zone id 0 against zone
// id 0 is matched by a `from-zone any to-zone any permit` rule with no zone
// guard, citing #6682. That was the PROBLEM STATEMENT of a CLOSED issue, not
// current behaviour. Two mechanisms make it false: #3110 fenced every rule
// tier against zone 0, so a wildcard never reaches a zero pair, and #6682 then
// made an unzoned INGRESS an explicit deny. The corrected version was ALREADY
// written in this repo — compiler_wireguard_plaintext_warn_5618_test.go says
// the older claim "was wrong" — before I asserted the superseded one.
//
// The assertions below are unchanged and still correct, because they never
// depended on that claim: they assert that no ACCEPTED prefix may carry zeroed
// forwarding fields, which is a property of the decoder. A decoder must not
// report success for input it did not decode. What is deliberately NOT asserted
// here is any downstream consequence of an installed zero-zone session — that
// would need measuring, and asserting it unmeasured is how the original error
// got in.
//
// WHY A FULL PREFIX SWEEP RATHER THAN A FEW BOUNDARY CASES. The property is not
// "these particular lengths are rejected", it is "no accepted length yields
// zeroed forwarding fields". Sweeping every prefix and asserting the INVARIANT
// at each one covers the interiors of blocks as well as their boundaries, and it
// keeps holding if a future field moves a boundary — a boundary-listing test
// would silently stop covering the interior it was written for.
//
// WHAT IS DELIBERATELY STILL TOLERATED. Everything from the counters block
// onward stays length-gated, because those are genuine append-only wire
// extensions that older peers legitimately omit (#2170 Generation, #3301
// AppTimeout/PolicyCounterIdx, #5274 ConfigEpoch, #5212 RTFlowSessionID, #7095
// IngressIfaceFold). TestCrossVersionShortPayloadDecode and the #7095 truncation
// case pin that tolerance and must keep passing: the fix draws the line at
// forwarding semantics, not at "any short read".

func fullV4Record(t *testing.T) (dataplane.SessionKey, dataplane.SessionValue, []byte) {
	t.Helper()
	// Every field the assertion reads is NON-ZERO and distinct, so a decode that
	// silently substitutes a zero is caught. A fixture using the value the bug
	// falls back to would go green against the very defect it is written for.
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 1, 2, 3}, DstIP: [4]byte{10, 4, 5, 6},
		SrcPort: 1111, DstPort: 2222, Protocol: 6,
	}
	val := dataplane.SessionValue{
		State: dataplane.SessStateEstablished,
		// The forwarding-semantic block that truncation used to zero.
		SessionID: 0x1122334455667788, PolicyID: 0xABCD,
		IngressZone: 0x0101, EgressZone: 0x0202,
		NATSrcIP: 0x0A0B0C0D, NATDstIP: 0x0E0F1011,
		NATSrcPort: 3333, NATDstPort: 4444,
	}
	return key, val, encodeSessionV4Payload(key, val)
}

func TestTruncatedV4RecordNeverDecodesWithZeroedForwardingFields7175(t *testing.T) {
	_, val, full := fullV4Record(t)

	accepted := 0
	for n := 0; n <= len(full); n++ {
		_, got, ok := decodeSessionV4Payload(full[:n])
		if !ok {
			continue
		}
		accepted++
		// The invariant: anything ACCEPTED must carry the real forwarding
		// fields, never the zero the truncation used to substitute.
		if got.PolicyID != val.PolicyID {
			t.Fatalf("prefix of %d bytes decoded ok=true with PolicyID=%d, want %d — a truncated "+
				"record must not be accepted with a zeroed policy id (#7175)", n, got.PolicyID, val.PolicyID)
		}
		if got.IngressZone != val.IngressZone || got.EgressZone != val.EgressZone {
			t.Fatalf("prefix of %d bytes decoded ok=true with zones (%d,%d), want (%d,%d) — a "+
				"decoder must not report success for a record whose zone identity it never read",
				n, got.IngressZone, got.EgressZone, val.IngressZone, val.EgressZone)
		}
		if got.NATSrcIP != val.NATSrcIP || got.NATDstIP != val.NATDstIP ||
			got.NATSrcPort != val.NATSrcPort || got.NATDstPort != val.NATDstPort {
			t.Fatalf("prefix of %d bytes decoded ok=true with NAT (%d,%d,%d,%d), want (%d,%d,%d,%d) — "+
				"a session installed with no translation misforwards (#7175)",
				n, got.NATSrcIP, got.NATDstIP, got.NATSrcPort, got.NATDstPort,
				val.NATSrcIP, val.NATDstIP, val.NATSrcPort, val.NATDstPort)
		}
	}
	// Negative control. Without it "no accepted prefix violated the invariant"
	// is also what a decoder that rejects EVERYTHING reports — including the
	// complete record, which would break session sync entirely while this test
	// stayed green.
	if accepted == 0 {
		t.Fatal("no prefix decoded at all, so the sweep above asserted nothing: a decoder that " +
			"rejects every input would pass it. The complete record must still decode")
	}
	t.Logf("%d of %d prefix lengths accepted, all carrying intact forwarding fields", accepted, len(full)+1)
}

// The complete record must round-trip unchanged — the other half of the control:
// the fix must reject partial state without disturbing the valid path.
func TestCompleteV4RecordStillRoundTrips7175(t *testing.T) {
	key, val, full := fullV4Record(t)
	gotKey, got, ok := decodeSessionV4Payload(full)
	if !ok {
		t.Fatal("the complete record must decode")
	}
	if gotKey != key {
		t.Errorf("key round-trip: got %+v want %+v", gotKey, key)
	}
	if got.PolicyID != val.PolicyID || got.IngressZone != val.IngressZone ||
		got.EgressZone != val.EgressZone || got.SessionID != val.SessionID {
		t.Errorf("forwarding fields round-trip: got policy=%d zones=(%d,%d) id=%d",
			got.PolicyID, got.IngressZone, got.EgressZone, got.SessionID)
	}
}

func TestTruncatedV6RecordNeverDecodesWithZeroedForwardingFields7175(t *testing.T) {
	key := dataplane.SessionKeyV6{SrcPort: 1111, DstPort: 2222, Protocol: 6}
	key.SrcIP[0], key.DstIP[0] = 0x20, 0x30
	val := dataplane.SessionValueV6{
		State: dataplane.SessStateEstablished,
		// v6 splits NAT into its own block; both blocks are asserted.
		SessionID: 0x99AABBCC, PolicyID: 0x4321,
		IngressZone: 0x0303, EgressZone: 0x0404,
		NATSrcPort: 5555, NATDstPort: 6666,
	}
	val.NATSrcIP[0], val.NATDstIP[0] = 0x40, 0x50
	full := encodeSessionV6Payload(key, val)

	accepted := 0
	for n := 0; n <= len(full); n++ {
		_, got, ok := decodeSessionV6Payload(full[:n])
		if !ok {
			continue
		}
		accepted++
		if got.PolicyID != val.PolicyID || got.IngressZone != val.IngressZone || got.EgressZone != val.EgressZone {
			t.Fatalf("v6 prefix of %d bytes decoded ok=true with policy=%d zones=(%d,%d) (#7175)",
				n, got.PolicyID, got.IngressZone, got.EgressZone)
		}
		if got.NATSrcIP != val.NATSrcIP || got.NATDstIP != val.NATDstIP ||
			got.NATSrcPort != val.NATSrcPort || got.NATDstPort != val.NATDstPort {
			t.Fatalf("v6 prefix of %d bytes decoded ok=true with zeroed/incorrect NAT — v6 carries NAT "+
				"in its own 36-byte block, which was separately fail-open (#7175)", n)
		}
	}
	if accepted == 0 {
		t.Fatal("no v6 prefix decoded at all — the sweep asserted nothing")
	}
}

// C179-075, the sibling on the DHCP full-set path. A full-set push REPLACES the
// peer lease set, so accepting a prefix DELETES every lease past the cut on the
// standby.
func TestDHCPFullSetRejectsARecordCutMidStream7175(t *testing.T) {
	in := []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.0.1", SubnetID: 1, Remaining: 10, ValidLife: 10},
		{Family: 4, Address: "10.0.0.2", SubnetID: 1, Remaining: 20, ValidLife: 20},
	}
	full := encodeDHCPLeasePayload(in)

	// Positive control FIRST: without it, a decoder that rejects everything
	// passes the rejection cell below.
	if out, ok := decodeDHCPLeasePayload(full); !ok || len(out) != 2 {
		t.Fatalf("control: the complete lease set must decode (ok=%v, %d leases)", ok, len(out))
	}

	// Cut the LAST record in half. Its length prefix still claims the full
	// length, so the frame is framed-but-truncated — the exact shape that used
	// to return a silently shortened set.
	cut := full[:len(full)-6]
	out, ok := decodeDHCPLeasePayload(cut)
	if ok {
		t.Errorf("a lease record cut mid-stream decoded ok=true with %d of %d leases — a full-set "+
			"push replaces the set, so the standby would silently drop the rest (C179-075)", len(out), len(in))
	}
	if len(out) != 0 {
		t.Errorf("a rejected decode must yield no leases, got %d — the caller stores what it is "+
			"handed, so a non-empty prefix here still replaces the set", len(out))
	}
}

// The deliberately TOLERATED case, pinned so the rejection above cannot quietly
// widen into it. An over-declared count whose records all arrived WHOLE loses no
// data — only the sender's count was wrong — and this is the contract
// TestDHCPLeasePayload_TruncatedStream already documents.
func TestDHCPFullSetStillToleratesAnOverDeclaredCount7175(t *testing.T) {
	in := []dhcpserver.SyncLease{
		{Family: 4, Address: "10.0.0.1", SubnetID: 1, Remaining: 10, ValidLife: 10},
		{Family: 4, Address: "10.0.0.2", SubnetID: 1, Remaining: 20, ValidLife: 20},
	}
	payload := encodeDHCPLeasePayload(in)
	binary.LittleEndian.PutUint32(payload[:4], 5) // claim 5, ship 2 complete records
	out, ok := decodeDHCPLeasePayload(payload)
	if !ok || len(out) != 2 {
		t.Fatalf("an over-declared count with every record whole must still decode "+
			"(ok=%v, %d leases, want true/2). #7175 rejects data LOSS, not a wrong count", ok, len(out))
	}
}
