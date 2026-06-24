package snmp

import (
	"bytes"
	"crypto/hmac"
	"testing"
)

// buildV3ContextRequest builds a complete SNMPv3 authNoPriv GetRequest for a
// single OID, carrying the supplied scopedPDU contextName. boots/tm are set to
// the agent's values so the request passes the timeliness window; the focus is
// the context gate, not timeliness. The PDU is a GetRequest for oid so the
// default-context path returns a real data varbind and the non-default path can
// be asserted to return an empty-view exception instead.
func buildV3ContextRequest(t *testing.T, authProto, userName string, engineID, authKey []byte, boots, tm int, contextName []byte, oid []int) []byte {
	return buildV3ContextRequestPDU(t, authProto, userName, engineID, authKey, boots, tm, contextName, oid, pduGetRequest)
}

// buildV3ContextRequestPDU is buildV3ContextRequest with a selectable PDU tag.
func buildV3ContextRequestPDU(t *testing.T, authProto, userName string, engineID, authKey []byte, boots, tm int, contextName []byte, oid []int, pduTag byte) []byte {
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
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlagAuth})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	// scopedPDU: contextEngineID, contextName, GetRequest PDU for one OID.
	scopedBody := berEncodeTLV(tagOctetString, engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, contextName)...)
	vb := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oid))
	vb = append(vb, berEncodeTLV(tagNull, nil)...)
	vbList := berEncodeTLV(tagSequence, berEncodeTLV(tagSequence, vb))
	pduBody := berEncodeIntegerTLV(77)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbList...)
	scopedBody = append(scopedBody, berEncodeTLV(pduTag, pduBody)...)
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
	computed := mac.Sum(nil)[:truncLen]
	copy(wholeMsg[start:end], computed)
	return wholeMsg
}

// scopedContextName decodes the contextName field out of a v3 GetResponse so a
// test can assert the agent echoes the requested context. It walks: outer
// SEQUENCE -> version -> msgGlobalData SEQUENCE -> msgSecurityParameters OCTET
// STRING -> scopedPDU SEQUENCE -> contextEngineID, contextName.
func scopedContextName(t *testing.T, resp []byte) []byte {
	t.Helper()
	tag, msgBody, err := berDecodeHeader(resp)
	if err != nil || tag != tagSequence {
		t.Fatalf("resp: outer SEQUENCE decode failed: %v", err)
	}
	_, rest, err := berDecodeInteger(msgBody) // version
	if err != nil {
		t.Fatalf("resp: version decode failed: %v", err)
	}
	hdrLen := berEncodedLen(rest) // msgGlobalData SEQUENCE
	if hdrLen <= 0 || hdrLen >= len(rest) {
		t.Fatalf("resp: msgGlobalData length error")
	}
	afterHdr := rest[hdrLen:]
	_, afterSec, err := berDecodeOctetString(afterHdr) // msgSecurityParameters
	if err != nil {
		t.Fatalf("resp: msgSecurityParameters decode failed: %v", err)
	}
	tag, scopedBody, err := berDecodeHeader(afterSec) // scopedPDU SEQUENCE
	if err != nil || tag != tagSequence {
		t.Fatalf("resp: scopedPDU not a SEQUENCE (tag=0x%02x err=%v)", tag, err)
	}
	_, ctxRest, err := berDecodeOctetString(scopedBody) // contextEngineID
	if err != nil {
		t.Fatalf("resp: contextEngineID decode failed: %v", err)
	}
	ctxName, _, err := berDecodeOctetString(ctxRest) // contextName
	if err != nil {
		t.Fatalf("resp: contextName decode failed: %v", err)
	}
	return ctxName
}

// TestV3DefaultContextServed verifies that a GetRequest with an EMPTY (default)
// contextName still returns the real MIB value for sysDescr — i.e. the context
// gate does not regress the default context.
func TestV3DefaultContextServed(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	pkt := buildV3ContextRequest(t, "sha", "tuser", engineID, authKey, 5, 1000, nil, oidSysDescr)
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if resp == nil {
		t.Fatal("default-context request: got nil response")
	}
	// The default sysDescr value must appear in the response.
	if !bytes.Contains(resp, []byte("xpf stateful firewall")) {
		t.Fatal("default-context request: response missing sysDescr value")
	}
	if got := scopedContextName(t, resp); len(got) != 0 {
		t.Fatalf("default-context request: response contextName = %q, want empty", got)
	}
}

// TestV3NonDefaultContextEmptyView is the core context-gate test. A GetRequest
// for a NON-DEFAULT context ("vrf-red") must NOT be served default-context data:
// the sysDescr value must be absent and the varbind must be a noSuchInstance
// exception. fail-on-revert: removing the `if !defaultContext` gate in the
// GetRequest branch makes this request return the sysDescr value -> red.
func TestV3NonDefaultContextEmptyView(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	ctx := []byte("vrf-red")
	pkt := buildV3ContextRequest(t, "sha", "tuser", engineID, authKey, 5, 1000, ctx, oidSysDescr)
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if resp == nil {
		t.Fatal("non-default-context request: got nil response (should be empty-view, not dropped)")
	}
	// Must NOT leak the default-context sysDescr value.
	if bytes.Contains(resp, []byte("xpf stateful firewall")) {
		t.Fatal("non-default-context request: response leaked default-context sysDescr value")
	}
	// Varbind must be a noSuchInstance exception (tag 0x81).
	if !bytes.Contains(resp, []byte{tagNoSuchInstance, 0x00}) {
		t.Fatal("non-default-context request: response missing noSuchInstance exception")
	}
	// The requested contextName must be echoed back.
	if got := scopedContextName(t, resp); !bytes.Equal(got, ctx) {
		t.Fatalf("non-default-context request: response contextName = %q, want %q", got, ctx)
	}
}

// TestV3NonDefaultContextGetNextEndOfMib verifies the GetNext branch returns
// endOfMibView (not default-context data) for a non-default context.
// fail-on-revert: removing the GetNext-branch gate makes this leak the first
// MIB OID's value.
func TestV3NonDefaultContextGetNextEndOfMib(t *testing.T) {
	a, engineID, authKey := newTimelinessAgent(t, 5, 1000)
	ctx := []byte("vrf-blue")
	// GetNext on sysDescr would normally return sysObjectID's value.
	pkt := buildV3ContextRequestNext(t, "sha", "tuser", engineID, authKey, 5, 1000, ctx, oidSysDescr)
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if resp == nil {
		t.Fatal("non-default-context GetNext: got nil response")
	}
	if bytes.Contains(resp, []byte("xpf stateful firewall")) {
		t.Fatal("non-default-context GetNext: leaked default-context data")
	}
	if !bytes.Contains(resp, []byte{tagEndOfMibView, 0x00}) {
		t.Fatal("non-default-context GetNext: missing endOfMibView exception")
	}
	if got := scopedContextName(t, resp); !bytes.Equal(got, ctx) {
		t.Fatalf("non-default-context GetNext: contextName = %q, want %q", got, ctx)
	}
}

// buildV3ContextRequestNext is buildV3ContextRequest with a GetNext PDU tag.
func buildV3ContextRequestNext(t *testing.T, authProto, userName string, engineID, authKey []byte, boots, tm int, contextName []byte, oid []int) []byte {
	t.Helper()
	return buildV3ContextRequestPDU(t, authProto, userName, engineID, authKey, boots, tm, contextName, oid, pduGetNextRequest)
}
