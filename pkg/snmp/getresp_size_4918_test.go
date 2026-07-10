package snmp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// buildV2cGetRequestMulti constructs an SNMP v2c GET request for a LIST of
// OIDs (the single-OID buildV2cGetRequest lives in agent_set_test.go; the
// GETNEXT sibling buildV2cGetNextRequest lives in getbulk_size_test.go). The
// two integer fields after request-id (error-status / error-index) are zero in
// a request.
func buildV2cGetRequestMulti(community string, requestID int, oids [][]int) []byte {
	var vbList []byte
	for _, oid := range oids {
		oidBytes := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oid))
		valBytes := berEncodeTLV(tagNull, nil)
		vbList = append(vbList, berEncodeTLV(tagSequence, append(oidBytes, valBytes...))...)
	}
	vbListEnc := berEncodeTLV(tagSequence, vbList)

	pduBody := berEncodeIntegerTLV(requestID)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...) // error-status
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...) // error-index
	pduBody = append(pduBody, vbListEnc...)
	pdu := berEncodeTLV(pduGetRequest, pduBody)

	msg := berEncodeIntegerTLV(snmpVersion2c)
	msg = append(msg, berEncodeTLV(tagOctetString, []byte(community))...)
	msg = append(msg, pdu...)
	return berEncodeTLV(tagSequence, msg)
}

// ifDescrOIDs returns ifTable ifDescr (column 2) OIDs for ifIndex 1..n. With
// manyIfData(n)'s long IfDescr values, a GET/GETNEXT over enough of them
// overflows the 4096-byte response ceiling.
func ifDescrOIDs(n int) [][]int {
	oids := make([][]int, 0, n)
	for i := 1; i <= n; i++ {
		oid := append(append([]int{}, oidIfTablePrefix...), 2, i)
		oids = append(oids, oid)
	}
	return oids
}

// TestV2cGet_OversizedReturnsTooBig covers residual (1) of #4918 for plain GET:
// a GET naming many long-valued OIDs would encode a response larger than
// maxPacketSize. The response must be bounded — replaced with tooBig + empty
// varbinds — never emitted over-size. fail-on-revert: drop boundGetResponse's
// size check and this response exceeds maxPacketSize with errNoError.
func TestV2cGet_OversizedReturnsTooBig(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(func() []IfData { return manyIfData(60) })

	req := buildV2cGetRequestMulti("public", 1, ifDescrOIDs(60))
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp) > maxPacketSize {
		t.Fatalf("GET response %d bytes exceeds maxPacketSize %d (size cap not applied)", len(resp), maxPacketSize)
	}
	errStatus, oids := v2cResponseVarbinds(t, resp)
	if errStatus != errTooBig {
		t.Fatalf("error-status = %d, want tooBig (%d) for an oversized GET", errStatus, errTooBig)
	}
	if len(oids) != 0 {
		t.Fatalf("tooBig response must carry an empty varbind list, got %d varbinds", len(oids))
	}
}

// TestV2cGetNext_OversizedReturnsTooBig is residual (1) for GETNEXT: the same
// fixed 1:1 varbind contract, so an oversized GETNEXT is also replaced with
// tooBig rather than emitted over-size.
func TestV2cGetNext_OversizedReturnsTooBig(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(func() []IfData { return manyIfData(60) })

	req := buildV2cGetNextRequest("public", 2, ifDescrOIDs(60))
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp) > maxPacketSize {
		t.Fatalf("GETNEXT response %d bytes exceeds maxPacketSize %d (size cap not applied)", len(resp), maxPacketSize)
	}
	errStatus, oids := v2cResponseVarbinds(t, resp)
	if errStatus != errTooBig {
		t.Fatalf("error-status = %d, want tooBig (%d) for an oversized GETNEXT", errStatus, errTooBig)
	}
	if len(oids) != 0 {
		t.Fatalf("tooBig response must carry an empty varbind list, got %d varbinds", len(oids))
	}
}

// TestV2cGet_SmallUnchanged: a normal small GET that fits returns all its
// varbinds with noError — the size bound must not disturb the common path.
func TestV2cGet_SmallUnchanged(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(func() []IfData { return manyIfData(2) })

	req := buildV2cGetRequestMulti("public", 3, ifDescrOIDs(2))
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp) > maxPacketSize {
		t.Fatalf("small GET response %d bytes unexpectedly large", len(resp))
	}
	errStatus, oids := v2cResponseVarbinds(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError for a small GET", errStatus)
	}
	if len(oids) != 2 {
		t.Fatalf("expected 2 varbinds for a 2-OID GET, got %d", len(oids))
	}
}

// TestTrimToFit_BinarySearch covers residual (2) of #4918: trimToFit must find
// the largest fitting prefix with O(log n) rebuilds, not O(n). The build func
// returns a length monotonic in the prefix size and counts its invocations.
// With 1000 varbinds trimmed to a 10-varbind prefix, the old decrement-and-
// rebuild would call build ~991 times; binary search calls it a couple dozen.
func TestTrimToFit_BinarySearch(t *testing.T) {
	const n = 1000
	vbs := make([]varbind, n)

	builds := 0
	// Encoded length = 10*count + 5, strictly increasing in the prefix length.
	build := func(sub []varbind) []byte {
		builds++
		return make([]byte, len(sub)*10+5)
	}

	const maxSize = 105 // fits exactly len==10 (10*10+5)
	resp, ok := trimToFit(vbs, maxSize, build)
	if !ok {
		t.Fatal("trimToFit reported no fit; a 10-varbind prefix fits maxSize=105")
	}
	if len(resp) != 105 {
		t.Fatalf("trimmed response = %d bytes, want 105 (the largest fitting prefix)", len(resp))
	}
	// Binary search over 1000 items is ~log2(1000)+2 ≈ 12 builds; allow slack.
	// The old linear decrement-and-rebuild would be ~991 — far over this bound.
	if builds > 40 {
		t.Fatalf("trimToFit made %d build calls; expected O(log n) (binary search), not O(n)", builds)
	}
}

// TestTrimToFit_NothingFits: when even a zero-varbind response exceeds maxSize,
// trimToFit reports no fit so the caller falls back to tooBig.
func TestTrimToFit_NothingFits(t *testing.T) {
	vbs := make([]varbind, 5)
	build := func(sub []varbind) []byte { return make([]byte, len(sub)*10+50) }
	if _, ok := trimToFit(vbs, 1, build); ok {
		t.Fatal("trimToFit reported a fit for a 1-byte budget; tooBig fallback would be skipped")
	}
}
