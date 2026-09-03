package cluster

import (
	"math"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

func sampleIdleLease() userspace.IdleLeaseWire {
	return userspace.IdleLeaseWire{
		Pool:           "P",
		Protocol:       6,
		SrcIP:          "10.0.61.50",
		SrcPort:        40000,
		RemoteIP:       "8.8.8.8",
		RemotePort:     443,
		TranslatedIP:   "203.0.113.1",
		TranslatedPort: 1024,
		AddressOnly:    false,
		RemainingNs:    270_000_000_000,
		TimeoutNs:      300_000_000_000,
	}
}

// #8121: every field survives the wire. A field silently dropped here becomes a
// zero on the standby — and a zero `RemainingNs` is not an obvious failure, it
// is a lease the receiver discards, so the symptom would be "the feature does
// nothing" rather than a decode error.
func TestPersistentNatLeasePayload_RoundTrip(t *testing.T) {
	in := []userspace.IdleLeaseWire{
		sampleIdleLease(),
		{
			// permit-any-remote-host: an EMPTY remote must stay empty rather
			// than round-tripping into an address.
			Pool:           "Q",
			Protocol:       17,
			SrcIP:          "2001:db8::1",
			SrcPort:        5000,
			TranslatedIP:   "203.0.113.9",
			TranslatedPort: 2048,
			AddressOnly:    true,
			RemainingNs:    1,
			TimeoutNs:      60_000_000_000,
		},
	}
	out, ok := decodePersistentNatLeasePayload(encodePersistentNatLeasePayload(in))
	if !ok {
		t.Fatalf("a well-formed payload must decode completely")
	}
	if len(out) != len(in) {
		t.Fatalf("record count: got %d want %d", len(out), len(in))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Errorf("record %d round-trip mismatch:\n got %+v\nwant %+v", i, out[i], in[i])
		}
	}
}

// #4892 shape: a string field longer than the uint16 length prefix can describe
// must DROP that record, never narrow the prefix. A wrapped length misframes the
// peer's decode, so every record after it is read from the wrong offset — one
// unencodable lease would corrupt the whole set.
func TestPersistentNatLeaseEncode_OversizedFieldDropsOnlyThatRecord(t *testing.T) {
	good := sampleIdleLease()
	oversized := sampleIdleLease()
	oversized.Pool = strings.Repeat("p", math.MaxUint16+1)

	out, ok := decodePersistentNatLeasePayload(
		encodePersistentNatLeasePayload([]userspace.IdleLeaseWire{good, oversized, good}),
	)
	if !ok {
		t.Fatalf("dropping a record must leave the payload self-consistent, not truncated")
	}
	if len(out) != 2 {
		t.Fatalf("the oversized record must be dropped and the others kept: got %d records", len(out))
	}
	for i, rec := range out {
		if rec != good {
			t.Errorf("surviving record %d was corrupted by the dropped one: %+v", i, rec)
		}
	}
	// CONTROL: the same three records with a legal Pool encode to THREE, so the
	// count above is caused by the oversize and not by the fixture.
	oversized.Pool = "R"
	ctl, ok := decodePersistentNatLeasePayload(
		encodePersistentNatLeasePayload([]userspace.IdleLeaseWire{good, oversized, good}),
	)
	if !ok || len(ctl) != 3 {
		t.Fatalf("control: a legal three-record set must encode to 3, got %d ok=%v", len(ctl), ok)
	}
}

// #7175 discipline: a full-set push REPLACES the peer's set, so a truncated
// payload must report INCOMPLETE. Returning a prefix as if it were the whole
// set would silently delete every lease past the truncation point.
func TestPersistentNatLeasePayload_TruncationReportsIncomplete(t *testing.T) {
	full := encodePersistentNatLeasePayload([]userspace.IdleLeaseWire{
		sampleIdleLease(), sampleIdleLease(),
	})
	// CONTROL: the untruncated payload decodes completely, so each failure
	// below is caused by the cut and not by a malformed fixture.
	if _, ok := decodePersistentNatLeasePayload(full); !ok {
		t.Fatalf("control: the full payload must decode completely")
	}
	for cut := 1; cut < len(full); cut++ {
		if _, ok := decodePersistentNatLeasePayload(full[:cut]); ok {
			t.Fatalf("a payload truncated to %d/%d bytes must report incomplete", cut, len(full))
		}
	}
}
