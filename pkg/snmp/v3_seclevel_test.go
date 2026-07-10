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

	enc, privParams, err := encryptAES128(privKey, scopedPDU, boots, reqTime)
	if err != nil || enc == nil {
		t.Fatalf("encryptAES128 failed building noAuthPriv request: %v", err)
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

// buildV3NoAuthNoPrivRequest builds an SNMPv3 GetRequest at the noAuthNoPriv
// security level (msgFlags = 0, empty auth/priv params, plaintext scopedPDU).
func buildV3NoAuthNoPrivRequest(userName string, engineID []byte, boots, reqTime int) []byte {
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
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte(userName))...)
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
	return berEncodeTLV(tagSequence, msgBody)
}

// TestSecLevel_AuthPrivUserMinLevel is the #4897 security regression: an
// authPriv-configured user carries a per-user minimum security level. Requests
// below that floor MUST be dropped, not served:
//
//   - noAuthNoPriv (flags = 0): the auth AND priv gates would be skipped and the
//     plaintext scopedPDU served without any password — an auth+confidentiality
//     bypass. MUST be dropped ("nil").
//   - authNoPriv (auth set, priv clear): authentication is proven but privacy is
//     stripped, so a configured-encrypted user is answered in the clear. MUST be
//     dropped ("nil").
//   - authPriv (both set): the configured level. MUST be served (decryptable
//     GetResponse).
//
// fail-on-revert: removing the min-security-level floor in handleV3Packet makes
// the noAuthNoPriv case decode+serve the plaintext PDU and the authNoPriv case
// pass auth then serve the plaintext PDU — both classify as "response", failing
// this test. That is the exact hole.
func TestSecLevel_AuthPrivUserMinLevel(t *testing.T) {
	const boots = 5
	const reqTime = 1000

	t.Run("noAuthNoPriv_dropped", func(t *testing.T) {
		a, engineID, _, _ := newAuthPrivAgent(t, boots, reqTime)
		pkt := buildV3NoAuthNoPrivRequest("puser", engineID, boots, reqTime)
		a.lastPacket = pkt
		resp := driveV3(t, a, pkt)
		if got := classifyV3Response(t, resp); got != "nil" {
			t.Fatalf("authPriv user queried at noAuthNoPriv: got %q, want %q "+
				"(below the user's minimum level, must be dropped)", got, "nil")
		}
	})

	t.Run("authNoPriv_dropped", func(t *testing.T) {
		a, engineID, authKey, _ := newAuthPrivAgent(t, boots, reqTime)
		pkt := buildV3TimedRequest(t, "sha", "puser", engineID, authKey, boots, reqTime)
		a.lastPacket = pkt
		resp := driveV3(t, a, pkt)
		if got := classifyV3Response(t, resp); got != "nil" {
			t.Fatalf("authPriv user queried at authNoPriv: got %q, want %q "+
				"(privacy is configured, must be dropped)", got, "nil")
		}
	})

	t.Run("authPriv_served", func(t *testing.T) {
		a, engineID, authKey, privKey := newAuthPrivAgent(t, boots, reqTime)
		pkt := buildV3AuthPrivAESRequest(t, "puser", engineID, authKey, privKey,
			boots, reqTime, boots, reqTime)
		a.lastPacket = pkt
		resp := driveV3(t, a, pkt)
		if !decodeV3AuthPrivResponse(t, resp, privKey) {
			t.Fatal("authPriv user queried at authPriv was not served with a " +
				"decryptable GetResponse (the configured level must be answered)")
		}
	})
}

// TestSecLevel_AuthNoPrivUserMinLevel covers the auth-only floor: an
// authNoPriv-configured user (auth key, no priv key) must reject a
// noAuthNoPriv request but still be served at authNoPriv.
//
// fail-on-revert: without the auth floor the noAuthNoPriv request is served in
// the clear ("response"), failing the first case.
func TestSecLevel_AuthNoPrivUserMinLevel(t *testing.T) {
	const boots = 5
	const reqTime = 1000

	t.Run("noAuthNoPriv_dropped", func(t *testing.T) {
		a, engineID, _ := newTimelinessAgent(t, boots, reqTime)
		pkt := buildV3NoAuthNoPrivRequest("tuser", engineID, boots, reqTime)
		a.lastPacket = pkt
		resp := driveV3(t, a, pkt)
		if got := classifyV3Response(t, resp); got != "nil" {
			t.Fatalf("authNoPriv user queried at noAuthNoPriv: got %q, want %q "+
				"(below the user's minimum level, must be dropped)", got, "nil")
		}
	})

	t.Run("authNoPriv_served", func(t *testing.T) {
		a, engineID, authKey := newTimelinessAgent(t, boots, reqTime)
		pkt := buildV3TimedRequest(t, "sha", "tuser", engineID, authKey, boots, reqTime)
		a.lastPacket = pkt
		resp := driveV3(t, a, pkt)
		if got := classifyV3Response(t, resp); got != "response" {
			t.Fatalf("authNoPriv user queried at authNoPriv: got %q, want a data "+
				"GetResponse (the configured level must be answered)", got)
		}
	})
}
