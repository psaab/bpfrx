package snmp

import (
	"testing"
)

// buildV3PrivOnlyRequest builds an SNMPv3 message that requests PRIVACY WITHOUT
// AUTHENTICATION (msgFlags = msgFlagPriv only — the invalid noAuthPriv security
// level RFC 3414 §5 forbids). The scopedPDU is a real AES-128-CFB encrypted
// GetRequest so that, absent the guard, the agent would decrypt and execute it.
// authParams is left empty because a noAuthPriv message carries no HMAC; the
// agent must reject the message before ever consulting authParams.
func buildV3PrivOnlyRequest(t *testing.T, userName string, engineID, privKey []byte, boots, reqTime int) []byte {
	t.Helper()

	// scopedPDU: contextEngineID, contextName, empty GetRequest PDU.
	scopedBody := berEncodeTLV(tagOctetString, engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, nil)...)
	pduBody := berEncodeIntegerTLV(123)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeTLV(tagSequence, nil)...)
	scopedBody = append(scopedBody, berEncodeTLV(pduGetRequest, pduBody)...)
	scopedPDU := berEncodeTLV(tagSequence, scopedBody)

	enc, privParams := encryptAES128(privKey, scopedPDU, boots, reqTime)
	if enc == nil {
		t.Fatal("encryptAES128 returned nil building noAuthPriv request")
	}
	encOctet := berEncodeTLV(tagOctetString, enc)

	// USM params with EMPTY authParams (no auth performed by the sender).
	usmFields := berEncodeTLV(tagOctetString, engineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(boots)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(reqTime)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte(userName))...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // authParams empty
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, privParams)...)
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	// Header flags: PRIVACY ONLY (0x02) — the forbidden noAuthPriv combination.
	hdr := berEncodeIntegerTLV(11)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlagPriv})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	msgBody = append(msgBody, encOctet...)
	return berEncodeTLV(tagSequence, msgBody)
}

// TestSecLevel_NoAuthPrivRejected is the core #2681 security regression test.
//
// A request with msgFlags = msgFlagPriv (privacy set, authentication clear) is
// the noAuthPriv level RFC 3414 forbids. The agent MUST drop it: it must not
// decrypt the scopedPDU and must not execute the carried GetRequest, so the
// result is nil (no GetResponse, no report).
//
// fail-on-revert: removing the noAuthPriv guard in handleV3Packet lets the
// auth-skip + decrypt path run, the encrypted GetRequest is decrypted and
// served, and the agent emits a (priv-flagged) GetResponse -> classifyV3Response
// returns "response" -> this test fails. That is the exact security hole.
func TestSecLevel_NoAuthPrivRejected(t *testing.T) {
	const boots = 5
	const reqTime = 1000
	a, engineID, _, privKey := newAuthPrivAgent(t, boots, reqTime)

	pkt := buildV3PrivOnlyRequest(t, "puser", engineID, privKey, boots, reqTime)
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if got := classifyV3Response(t, resp); got != "nil" {
		t.Fatalf("noAuthPriv (msgFlags=0x02) request: got %q, want %q (must be dropped, "+
			"not decrypted or executed)", got, "nil")
	}
}

// TestSecLevel_NoAuthNoPrivStillServed confirms the noAuthNoPriv level (both
// flags clear) is unaffected by the guard and still served. The agent has a
// user with auth/priv keys, but a request that sets neither flag carries no
// HMAC and is processed in the clear (this matches the pre-#2681 behavior; the
// guard only fires when priv is set and auth is clear).
func TestSecLevel_NoAuthNoPrivStillServed(t *testing.T) {
	const boots = 5
	const reqTime = 1000
	a, engineID, _, _ := newAuthPrivAgent(t, boots, reqTime)

	// noAuthNoPriv GetRequest: flags = 0, empty auth/priv params, plaintext PDU.
	scopedBody := berEncodeTLV(tagOctetString, engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, nil)...)
	pduBody := berEncodeIntegerTLV(55)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeTLV(tagSequence, nil)...)
	scopedBody = append(scopedBody, berEncodeTLV(pduGetRequest, pduBody)...)
	scopedPDU := berEncodeTLV(tagSequence, scopedBody)

	usmFields := berEncodeTLV(tagOctetString, engineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(boots)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(reqTime)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte("puser"))...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // authParams
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // privParams
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	hdr := berEncodeIntegerTLV(3)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{0x00})...) // no flags
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	msgBody = append(msgBody, scopedPDU...)
	pkt := berEncodeTLV(tagSequence, msgBody)
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if got := classifyV3Response(t, resp); got != "response" {
		t.Fatalf("noAuthNoPriv request: got %q, want a data GetResponse (valid level "+
			"must still be served)", got)
	}
}
