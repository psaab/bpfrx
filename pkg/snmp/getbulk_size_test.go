package snmp

import (
	"crypto/hmac"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// manyIfData returns n synthetic interfaces with long descriptions/aliases so a
// GETBULK walk over the ifTable/ifXTable produces enough bytes to overflow the
// 4096-byte response ceiling well before maxRepetitions is exhausted. The fix
// must trim the response; without the size cap the encoded datagram exceeds
// 4096 (the fail-on-revert lever).
func manyIfData(n int) []IfData {
	long := "interface-with-a-deliberately-long-description-to-inflate-the-getbulk-response-AAAAAAAAAAAAAAAA"
	out := make([]IfData, n)
	for i := 0; i < n; i++ {
		out[i] = IfData{
			IfIndex:     i + 1,
			IfDescr:     long,
			IfType:      6,
			IfMtu:       1500,
			IfSpeed:     1000000000,
			AdminStatus: 1,
			OperStatus:  1,
			InOctets:    4000000000,
			OutOctets:   4000000000,
			IfName:      long,
			HCInOctets:  18000000000000000000,
			HCOutOctets: 18000000000000000000,
			IfHighSpeed: 1000,
			IfAlias:     long,
		}
	}
	return out
}

// buildV2cGetBulkRequest constructs an SNMP v2c GETBULK request for a list of
// start OIDs with the given non-repeaters / max-repetitions.
func buildV2cGetBulkRequest(community string, requestID, nonRepeaters, maxReps int, oids [][]int) []byte {
	var vbList []byte
	for _, oid := range oids {
		oidBytes := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oid))
		valBytes := berEncodeTLV(tagNull, nil)
		vbList = append(vbList, berEncodeTLV(tagSequence, append(oidBytes, valBytes...))...)
	}
	vbListEnc := berEncodeTLV(tagSequence, vbList)

	pduBody := berEncodeIntegerTLV(requestID)
	pduBody = append(pduBody, berEncodeIntegerTLV(nonRepeaters)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(maxReps)...)
	pduBody = append(pduBody, vbListEnc...)
	pdu := berEncodeTLV(pduGetBulkRequest, pduBody)

	msg := berEncodeIntegerTLV(snmpVersion2c)
	msg = append(msg, berEncodeTLV(tagOctetString, []byte(community))...)
	msg = append(msg, pdu...)
	return berEncodeTLV(tagSequence, msg)
}

// v2cResponseVarbinds walks a v2c GetResponse to its varbind list and returns
// the decoded OIDs (one per varbind) so a test can assert the response is
// well-formed and find the last OID (the point a manager would continue a
// trimmed GETBULK walk from).
func v2cResponseVarbinds(t *testing.T, resp []byte) (errStatus int, oids [][]int) {
	t.Helper()
	tag, body, err := berDecodeHeader(resp)
	if err != nil || tag != tagSequence {
		t.Fatalf("resp: outer SEQUENCE: %v", err)
	}
	_, rest, err := berDecodeInteger(body) // version
	if err != nil {
		t.Fatalf("resp: version: %v", err)
	}
	_, rest, err = berDecodeOctetString(rest) // community
	if err != nil {
		t.Fatalf("resp: community: %v", err)
	}
	pduTag, pduBody, err := berDecodeHeader(rest)
	if err != nil || pduTag != pduGetResponse {
		t.Fatalf("resp: PDU header tag=0x%02x err=%v", pduTag, err)
	}
	_, pduRest, err := berDecodeInteger(pduBody) // request-id
	if err != nil {
		t.Fatalf("resp: request-id: %v", err)
	}
	errStatus, pduRest, err = berDecodeInteger(pduRest) // error-status
	if err != nil {
		t.Fatalf("resp: error-status: %v", err)
	}
	_, pduRest, err = berDecodeInteger(pduRest) // error-index
	if err != nil {
		t.Fatalf("resp: error-index: %v", err)
	}
	return errStatus, decodeVarbindOIDs(t, pduRest)
}

// decodeVarbindOIDs decodes the OID of every varbind in an encoded varbind-list
// SEQUENCE. It double-checks the response is well-formed: every varbind is a
// SEQUENCE whose first element is an OBJECT IDENTIFIER.
func decodeVarbindOIDs(t *testing.T, vbListTLV []byte) [][]int {
	t.Helper()
	tag, vbListBody, err := berDecodeHeader(vbListTLV)
	if err != nil || tag != tagSequence {
		t.Fatalf("varbind list: not a SEQUENCE (tag=0x%02x err=%v)", tag, err)
	}
	var oids [][]int
	remaining := vbListBody
	for len(remaining) > 0 {
		vbTotal := berEncodedLen(remaining)
		if vbTotal <= 0 || vbTotal > len(remaining) {
			t.Fatalf("varbind: bad length %d", vbTotal)
		}
		vbTag, vbBody, err := berDecodeHeader(remaining)
		if err != nil || vbTag != tagSequence {
			t.Fatalf("varbind: not a SEQUENCE (tag=0x%02x err=%v)", vbTag, err)
		}
		if len(vbBody) < 2 || vbBody[0] != tagObjectIdentifier {
			t.Fatalf("varbind: first element not an OID")
		}
		oidLen, oidLenBytes, err := berDecodeLength(vbBody[1:])
		if err != nil {
			t.Fatalf("varbind: OID length: %v", err)
		}
		oidStart := 1 + oidLenBytes
		oid, err := berDecodeOID(vbBody[oidStart : oidStart+oidLen])
		if err != nil {
			t.Fatalf("varbind: OID decode: %v", err)
		}
		oids = append(oids, oid)
		remaining = remaining[vbTotal:]
	}
	return oids
}

// TestV2cGetBulk_TrimsToFit covers (a): a GETBULK that would overflow the
// 4096-byte ceiling returns a trimmed, well-formed response that fits, with
// real data varbinds the manager can continue the walk from. fail-on-revert:
// remove the trimToFit cap in handleGetBulk and this response exceeds 4096.
func TestV2cGetBulk_TrimsToFit(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(func() []IfData { return manyIfData(50) })

	// Start the walk at the ifTable prefix and ask for 100 repetitions — far
	// more than fits in one 4096-byte datagram.
	req := buildV2cGetBulkRequest("public", 1, 0, 100, [][]int{oidIfTablePrefix})
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp) > maxPacketSize {
		t.Fatalf("response %d bytes exceeds maxPacketSize %d (size cap not applied)", len(resp), maxPacketSize)
	}
	errStatus, oids := v2cResponseVarbinds(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError (trim should not produce tooBig here)", errStatus)
	}
	if len(oids) == 0 {
		t.Fatal("trimmed response has no varbinds; manager cannot continue")
	}
	// The last OID must be a real walked OID (in the ifTable/ifXTable space),
	// i.e. something the manager can re-issue GETBULK from.
	last := oids[len(oids)-1]
	if !(oidHasPrefix(last, oidIfTablePrefix) || oidHasPrefix(last, oidIfXTablePrefix)) {
		t.Fatalf("last OID %v not in the walked table space; manager cannot continue", last)
	}
}

// TestV2cGetBulk_SmallUnchanged covers (c): a normal small GETBULK that fits is
// returned whole with all expected varbinds and no tooBig.
func TestV2cGetBulk_SmallUnchanged(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(func() []IfData { return manyIfData(1) })

	// 3 repetitions over the system group: tiny, fits comfortably.
	req := buildV2cGetBulkRequest("public", 2, 0, 3, [][]int{oidSysDescr})
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp) > maxPacketSize {
		t.Fatalf("small response %d bytes unexpectedly large", len(resp))
	}
	errStatus, oids := v2cResponseVarbinds(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError", errStatus)
	}
	if len(oids) != 3 {
		t.Fatalf("expected 3 varbinds for a small 3-repetition GETBULK, got %d", len(oids))
	}
}

// buildV3GetBulkRequest builds a complete SNMPv3 authNoPriv GETBULK request
// with a selectable advertised msgMaxSize, so a test can drive the
// min(msgMaxSize, maxPacketSize) bound and the 484-byte floor clamp.
func buildV3GetBulkRequest(t *testing.T, authProto, userName string, engineID, authKey []byte,
	boots, tm, msgMaxSize, nonRepeaters, maxReps int, oids [][]int) []byte {
	t.Helper()
	hashFn, _ := authHashFunc(authProto)
	if hashFn == nil {
		t.Fatalf("unknown auth proto %q", authProto)
	}
	truncLen := authTruncLen(authProto)

	authPlaceholder := make([]byte, truncLen)
	usmFields := berEncodeTLV(tagOctetString, engineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(boots)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(tm)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte(userName))...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, authPlaceholder)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // privParams
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	hdr := berEncodeIntegerTLV(11)
	hdr = append(hdr, berEncodeIntegerTLV(msgMaxSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlagAuth})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	var vbList []byte
	for _, oid := range oids {
		vb := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oid))
		vb = append(vb, berEncodeTLV(tagNull, nil)...)
		vbList = append(vbList, berEncodeTLV(tagSequence, vb)...)
	}
	vbListEnc := berEncodeTLV(tagSequence, vbList)

	pduBody := berEncodeIntegerTLV(77)
	pduBody = append(pduBody, berEncodeIntegerTLV(nonRepeaters)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(maxReps)...)
	pduBody = append(pduBody, vbListEnc...)

	scopedBody := berEncodeTLV(tagOctetString, engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, nil)...) // default context
	scopedBody = append(scopedBody, berEncodeTLV(pduGetBulkRequest, pduBody)...)
	scopedPDU := berEncodeTLV(tagSequence, scopedBody)

	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	msgBody = append(msgBody, scopedPDU...)
	wholeMsg := berEncodeTLV(tagSequence, msgBody)

	start, end, ok := usmAuthParamsRange(wholeMsg)
	if !ok || end-start != truncLen {
		t.Fatalf("usmAuthParamsRange failed on built request (ok=%v len=%d)", ok, end-start)
	}
	mac := hmac.New(hashFn, authKey)
	mac.Write(wholeMsg)
	copy(wholeMsg[start:end], mac.Sum(nil)[:truncLen])
	return wholeMsg
}

// v3GetBulkAgent builds an SNMPv3 agent with a single SHA authNoPriv user and
// returns the agent plus the localized auth key, engine ID, and current
// boots/time for request construction.
func v3GetBulkAgent(t *testing.T, ifs []IfData) (a *Agent, authKey, engineID []byte, boots, tm int) {
	t.Helper()
	a = NewAgentWithBootsPath(&config.SNMPConfig{
		V3Users: map[string]*config.SNMPv3User{
			"alice": {Name: "alice", AuthProtocol: "sha", AuthPassword: config.Secret("authpassword123")},
		},
	}, t.TempDir()+"/eb")
	a.SetIfDataFn(func() []IfData { return ifs })
	u := a.snapshotV3User("alice")
	if u == nil || u.authKey == nil {
		t.Fatal("v3 user alice not set up with auth key")
	}
	return a, u.authKey, a.engineID, a.engineBoots, a.engineTime()
}

// v3ResponseErrorStatus decodes an authNoPriv v3 GetResponse to its PDU
// error-status and the decoded varbind OIDs, walking scopedPDU -> PDU.
func v3ResponseErrorStatus(t *testing.T, resp []byte) (errStatus int, oids [][]int) {
	t.Helper()
	tag, msgBody, err := berDecodeHeader(resp)
	if err != nil || tag != tagSequence {
		t.Fatalf("resp: outer SEQUENCE: %v", err)
	}
	_, rest, err := berDecodeInteger(msgBody) // version
	if err != nil {
		t.Fatalf("resp: version: %v", err)
	}
	hdrLen := berEncodedLen(rest) // msgGlobalData SEQUENCE
	if hdrLen <= 0 || hdrLen >= len(rest) {
		t.Fatalf("resp: msgGlobalData length error")
	}
	rest = rest[hdrLen:]
	_, rest, err = berDecodeOctetString(rest) // msgSecurityParameters
	if err != nil {
		t.Fatalf("resp: secParams: %v", err)
	}
	tag, scopedBody, err := berDecodeHeader(rest) // scopedPDU SEQUENCE (plaintext, authNoPriv)
	if err != nil || tag != tagSequence {
		t.Fatalf("resp: scopedPDU SEQUENCE: %v", err)
	}
	_, scopedRest, err := berDecodeOctetString(scopedBody) // contextEngineID
	if err != nil {
		t.Fatalf("resp: contextEngineID: %v", err)
	}
	_, scopedRest, err = berDecodeOctetString(scopedRest) // contextName
	if err != nil {
		t.Fatalf("resp: contextName: %v", err)
	}
	pduTag, pduBody, err := berDecodeHeader(scopedRest)
	if err != nil || pduTag != pduGetResponse {
		t.Fatalf("resp: PDU tag=0x%02x err=%v", pduTag, err)
	}
	_, pduRest, err := berDecodeInteger(pduBody) // request-id
	if err != nil {
		t.Fatalf("resp: request-id: %v", err)
	}
	errStatus, pduRest, err = berDecodeInteger(pduRest) // error-status
	if err != nil {
		t.Fatalf("resp: error-status: %v", err)
	}
	_, pduRest, err = berDecodeInteger(pduRest) // error-index
	if err != nil {
		t.Fatalf("resp: error-index: %v", err)
	}
	return errStatus, decodeVarbindOIDs(t, pduRest)
}

// TestV3GetBulk_HonorsMsgMaxSize covers (d): a v3 GETBULK that advertises a
// msgMaxSize smaller than 4096 gets a response no larger than that advertised
// size, trimmed and well-formed.
func TestV3GetBulk_HonorsMsgMaxSize(t *testing.T) {
	a, authKey, engineID, boots, tm := v3GetBulkAgent(t, manyIfData(50))

	const advertised = 1024
	req := buildV3GetBulkRequest(t, "sha", "alice", engineID, authKey, boots, tm,
		advertised, 0, 100, [][]int{oidIfTablePrefix})
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp) > advertised {
		t.Fatalf("response %d bytes exceeds advertised msgMaxSize %d", len(resp), advertised)
	}
	errStatus, oids := v3ResponseErrorStatus(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError (should trim, not tooBig)", errStatus)
	}
	if len(oids) == 0 {
		t.Fatal("trimmed v3 response has no varbinds; manager cannot continue")
	}
}

// TestV3GetBulk_TinyMsgMaxSizeFloored covers the 484-byte floor: a v3 GETBULK
// advertising an absurdly small msgMaxSize (e.g. 1) is clamped up to 484, so
// the agent still returns at least the minimum-size response rather than
// truncating to nothing or honoring the bogus tiny value.
func TestV3GetBulk_TinyMsgMaxSizeFloored(t *testing.T) {
	a, authKey, engineID, boots, tm := v3GetBulkAgent(t, manyIfData(50))

	req := buildV3GetBulkRequest(t, "sha", "alice", engineID, authKey, boots, tm,
		1 /* absurd msgMaxSize */, 0, 100, [][]int{oidIfTablePrefix})
	resp := a.handlePacket(req)
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp) > minMsgMaxSize {
		t.Fatalf("response %d bytes exceeds the 484-byte floor budget", len(resp))
	}
	// Even at the floor a real interface row varbind fits, so the agent should
	// trim to a non-empty noError response, not tooBig.
	errStatus, oids := v3ResponseErrorStatus(t, resp)
	if errStatus != errNoError {
		t.Fatalf("error-status = %d, want noError at the 484 floor", errStatus)
	}
	if len(oids) == 0 {
		t.Fatal("floored v3 response has no varbinds")
	}
}

// TestV2cGetBulk_NothingFitsReturnsTooBig covers (b): the pathological case
// where even a single varbind cannot fit forces tooBig with an empty varbind
// list. We drive it through trimToFit directly with a 1-byte budget — no real
// SNMP message can be that small — so the tooBig fallback is exercised
// deterministically without depending on a particular OID's encoded length.
func TestV2cGetBulk_NothingFitsReturnsTooBig(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})
	a.SetIfDataFn(func() []IfData { return manyIfData(3) })

	vbs := []varbind{{oid: oidSysDescr, tag: tagOctetString, value: []byte("x")}}
	_, ok := trimToFit(vbs, 1, func(v []varbind) []byte {
		return a.buildResponse([]byte("public"), 1, errNoError, 0, v)
	})
	if ok {
		t.Fatal("trimToFit reported a fit for a 1-byte budget; tooBig fallback would be skipped")
	}

	// The handler converts !ok into a well-formed tooBig response with no
	// varbinds. Build it the same way handleGetBulk does and assert shape.
	resp := a.buildResponse([]byte("public"), 1, errTooBig, 0, nil)
	errStatus, oids := v2cResponseVarbinds(t, resp)
	if errStatus != errTooBig {
		t.Fatalf("error-status = %d, want tooBig (%d)", errStatus, errTooBig)
	}
	if len(oids) != 0 {
		t.Fatalf("tooBig response should carry no varbinds, got %d", len(oids))
	}
}

// TestEffectiveMaxSize pins the min/floor derivation directly.
func TestEffectiveMaxSize(t *testing.T) {
	cases := []struct {
		advertised, want int
	}{
		{0, minMsgMaxSize},             // bogus / mis-decoded -> floor
		{1, minMsgMaxSize},             // below floor -> floor
		{minMsgMaxSize, minMsgMaxSize}, // at floor
		{1024, 1024},                   // between floor and cap -> honored
		{maxPacketSize, maxPacketSize}, // at cap
		{65535, maxPacketSize},         // above cap -> cap
	}
	for _, c := range cases {
		if got := effectiveMaxSize(c.advertised); got != c.want {
			t.Errorf("effectiveMaxSize(%d) = %d, want %d", c.advertised, got, c.want)
		}
	}
}
