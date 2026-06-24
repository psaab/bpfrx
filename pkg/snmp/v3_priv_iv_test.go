package snmp

import (
	"bytes"
	"crypto/hmac"
	"testing"
)

// decodeV3AuthPrivResponse parses an authPriv SNMPv3 response, extracts the
// response's msgAuthoritativeEngineBoots/Time and privParams, decrypts the
// encrypted scopedPDU using those RECEIVED values (exactly as a conformant
// manager would per RFC 3826), and reports whether the decrypted scopedPDU
// carries a GetResponse PDU (0xa2 tag). Returns false on any decode/decrypt
// failure. This both verifies the request was served AND that the
// response-encrypt path round-trips (encrypt-IV boots/time == the boots/time
// written into the response header).
func decodeV3AuthPrivResponse(t *testing.T, resp, privKey []byte) bool {
	t.Helper()
	if resp == nil {
		return false
	}
	// outer SEQUENCE -> version -> rest.
	tag, msgBody, err := berDecodeHeader(resp)
	if err != nil || tag != tagSequence {
		return false
	}
	_, afterVer, err := berDecodeInteger(msgBody) // version
	if err != nil {
		return false
	}
	// HeaderData SEQUENCE.
	if _, _, err := berDecodeHeader(afterVer); err != nil {
		return false
	}
	headerTotalLen := berEncodedLen(afterVer)
	if headerTotalLen <= 0 || headerTotalLen >= len(afterVer) {
		return false
	}
	afterHeader := afterVer[headerTotalLen:]
	// USM SecurityParameters: OCTET STRING wrapping a SEQUENCE.
	secParamsRaw, afterSec, err := berDecodeOctetString(afterHeader)
	if err != nil {
		return false
	}
	tag, usmBody, err := berDecodeHeader(secParamsRaw)
	if err != nil || tag != tagSequence {
		return false
	}
	_, r, err := berDecodeOctetString(usmBody) // engineID
	if err != nil {
		return false
	}
	respBoots, r, err := berDecodeInteger(r)
	if err != nil {
		return false
	}
	respTime, r, err := berDecodeInteger(r)
	if err != nil {
		return false
	}
	_, r, err = berDecodeOctetString(r) // userName
	if err != nil {
		return false
	}
	_, r, err = berDecodeOctetString(r) // authParams
	if err != nil {
		return false
	}
	privParams, _, err := berDecodeOctetString(r) // privParams
	if err != nil {
		return false
	}
	// Encrypted scopedPDU is the next OCTET STRING after the USM params.
	encData, _, err := berDecodeOctetString(afterSec)
	if err != nil {
		return false
	}
	dec := decryptAES128(privKey, privParams, encData, respBoots, respTime)
	if dec == nil {
		return false
	}
	// decrypted is a scopedPDU SEQUENCE; a served request carries a GetResponse.
	if tag, _, err := berDecodeHeader(dec); err != nil || tag != tagSequence {
		return false
	}
	return bytes.IndexByte(dec, byte(pduGetResponse)) >= 0
}

// buildV3AuthPrivAESRequest builds a complete SNMPv3 authPriv GetRequest whose
// scopedPDU is encrypted with AES-128-CFB. The IV is derived from ivBoots/ivTime
// (the boots/time a manager would put in the message after discovery) per
// RFC 3826 §3.1.2.1, and the message carries msgBoots/msgTime in its USM
// parameters. For a conformant manager ivBoots==msgBoots and ivTime==msgTime;
// the test splits them only to prove the agent rebuilds the IV from the
// RECEIVED USM values rather than its local clock.
func buildV3AuthPrivAESRequest(t *testing.T, userName string, engineID, authKey, privKey []byte, msgBoots, msgTime, ivBoots, ivTime int) []byte {
	t.Helper()
	hashFn, _ := authHashFunc("sha")
	truncLen := authTruncLen("sha")

	// scopedPDU: contextEngineID, contextName, empty GetRequest PDU.
	scopedBody := berEncodeTLV(tagOctetString, engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, nil)...)
	pduBody := berEncodeIntegerTLV(99)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeTLV(tagSequence, nil)...)
	scopedBody = append(scopedBody, berEncodeTLV(pduGetRequest, pduBody)...)
	scopedPDU := berEncodeTLV(tagSequence, scopedBody)

	// Encrypt as a manager would: IV from ivBoots/ivTime.
	enc, privParams := encryptAES128(privKey, scopedPDU, ivBoots, ivTime)
	if enc == nil {
		t.Fatal("encryptAES128 returned nil building request")
	}
	encOctet := berEncodeTLV(tagOctetString, enc)

	authPlaceholder := make([]byte, truncLen)
	usmFields := berEncodeTLV(tagOctetString, engineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(msgBoots)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(msgTime)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte(userName))...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, authPlaceholder)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, privParams)...)
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	hdr := berEncodeIntegerTLV(7)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlagAuth | msgFlagPriv})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	msgBody = append(msgBody, encOctet...)
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

// newAuthPrivAgent builds an agent with one authPriv (SHA / AES-128) user, a
// fixed engineID, controlled engineBoots, and a startTime offset so engineTime()
// returns approximately wantTime. Returns the agent, engineID, authKey, privKey.
func newAuthPrivAgent(t *testing.T, boots, wantTime int) (*Agent, []byte, []byte, []byte) {
	t.Helper()
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xCA, 0xFE, 0xBA, 0xBE}
	hashFn, hashLen := authHashFunc("sha")
	authKey := passwordToKey("authpw-iv-test-123456", engineID, hashFn, hashLen)
	privKey := passwordToKey("privpw-iv-test-123456", engineID, hashFn, hashLen)

	a := &Agent{
		engineID:    engineID,
		engineBoots: boots,
		v3Users:     map[string]*usmUser{},
		startTime:   nowMinus(wantTime),
	}
	a.v3Users["puser"] = &usmUser{
		name:      "puser",
		authProto: "sha",
		authKey:   authKey,
		privProto: "aes128",
		privKey:   privKey,
	}
	return a, engineID, authKey, privKey
}

// TestAESDecryptIV_UsesReceivedBootsTime is the core #2640 regression test.
//
// The manager learned our boots/time via discovery and encrypted with an IV
// built from those values (reqTime=T). Our LOCAL clock has since advanced so
// engineTime() != T (here by +100s, still inside the ±150s window). With the
// fix the agent rebuilds the IV from the RECEIVED reqBoots/reqTime, so
// decryption succeeds and the request is served (a data GetResponse).
//
// fail-on-revert: reverting decryptPDU to a.engineBoots/a.engineTime() builds
// the IV from local time (T+100), CFB yields garbage, scopedPDU decode fails,
// and decodeV3Msg returns nil -> classifyV3Response reports "nil".
func TestAESDecryptIV_UsesReceivedBootsTime(t *testing.T) {
	const boots = 5
	const reqTime = 1000
	// Agent's local clock is 100s ahead of the time the manager used to encrypt
	// (engineTime() ~= 1100), but reqTime=1000 is well within the ±150s window
	// so checkTimeliness accepts.
	a, engineID, authKey, privKey := newAuthPrivAgent(t, boots, reqTime+100)

	pkt := buildV3AuthPrivAESRequest(t, "puser", engineID, authKey, privKey,
		boots, reqTime, boots, reqTime)
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if !decodeV3AuthPrivResponse(t, resp, privKey) {
		t.Fatal("skewed-clock authPriv request was not served with a decryptable " +
			"GetResponse (IV must use received reqBoots/reqTime, not the local clock)")
	}
}

// TestAESDecryptIV_SameTimeStillWorks confirms the no-skew case still round
// trips after the fix (no regression): reqTime == local engineTime.
func TestAESDecryptIV_SameTimeStillWorks(t *testing.T) {
	const boots = 5
	const reqTime = 2000
	a, engineID, authKey, privKey := newAuthPrivAgent(t, boots, reqTime)

	pkt := buildV3AuthPrivAESRequest(t, "puser", engineID, authKey, privKey,
		boots, reqTime, boots, reqTime)
	a.lastPacket = pkt

	resp := driveV3(t, a, pkt)
	if !decodeV3AuthPrivResponse(t, resp, privKey) {
		t.Fatal("same-time authPriv request was not served with a decryptable GetResponse")
	}
}

// TestAESDecryptIV_WrongIVFailsDecrypt is the unit-level inverse: encrypting
// with one (boots,time) and decrypting with a different time yields garbage,
// proving the IV time field is load-bearing (this is exactly the corruption the
// local-clock bug produced). It does not depend on the decodeV3Msg wiring.
func TestAESDecryptIV_WrongIVFailsDecrypt(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	plaintext := []byte("scopedPDU bytes that must survive a correct IV only")

	enc, pp := encryptAES128(key, plaintext, 5, 1000)
	if enc == nil {
		t.Fatal("encryptAES128 returned nil")
	}
	// Correct IV (matching time) recovers the plaintext.
	if dec := decryptAES128(key, pp, enc, 5, 1000); !bytesEqual(dec, plaintext) {
		t.Fatalf("matching-IV decrypt failed: got %q", dec)
	}
	// Wrong time in the IV (local-clock bug) must NOT recover the plaintext.
	if dec := decryptAES128(key, pp, enc, 5, 1100); bytesEqual(dec, plaintext) {
		t.Fatal("mismatched-IV decrypt recovered plaintext; IV time field is not load-bearing")
	}
}
