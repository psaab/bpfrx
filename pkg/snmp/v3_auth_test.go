package snmp

import (
	"bytes"
	"crypto/hmac"
	"testing"
)

// buildV3AuthPacket constructs a complete SNMPv3 authNoPriv message for the
// given user/engine parameters and returns the on-wire bytes together with
// the byte range of the (real) msgAuthenticationParameters value. The
// authParams are computed exactly as a conformant manager would: HMAC over
// the message with the authParams field present but zeroed, truncated to
// truncLen, then spliced back into that same field.
//
// longForm forces the msgSecurityParameters OCTET STRING (and therefore the
// outer SEQUENCE) to carry a long-form (>127) BER length by padding the
// engineID, exercising the multi-byte length path in the locator.
func buildV3AuthPacket(t *testing.T, authProto string, userName string, engineID []byte, authKey []byte, longForm bool) (pkt []byte, authStart, authEnd int) {
	t.Helper()

	hashFn, _ := authHashFunc(authProto)
	if hashFn == nil {
		t.Fatalf("unknown auth proto %q", authProto)
	}
	truncLen := authTruncLen(authProto)

	if longForm {
		// Pad the engineID so the USM sequence (and its OCTET STRING wrapper)
		// exceed 127 bytes, forcing long-form BER length encoding.
		engineID = append(append([]byte{}, engineID...), bytes.Repeat([]byte{0xAB}, 200)...)
	}

	// USM security parameters with a zeroed authParams placeholder.
	authPlaceholder := make([]byte, truncLen)
	usmFields := berEncodeTLV(tagOctetString, engineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(1)...) // engineBoots
	usmFields = append(usmFields, berEncodeIntegerTLV(2)...) // engineTime
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte(userName))...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, authPlaceholder)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // privParams (empty)
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	// Global header (msgID, maxSize, flags=auth, securityModel=USM).
	hdr := berEncodeIntegerTLV(42)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlagAuth})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	// Scoped PDU (plaintext) — contextEngineID, contextName, empty GetRequest.
	scopedBody := berEncodeTLV(tagOctetString, engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, nil)...)
	scopedBody = append(scopedBody, berEncodeTLV(0xA0, nil)...) // GetRequest PDU, empty
	scopedPDU := berEncodeTLV(tagSequence, scopedBody)

	// Assemble the whole message.
	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	msgBody = append(msgBody, scopedPDU...)
	wholeMsg := berEncodeTLV(tagSequence, msgBody)

	// Locate the authParams field (still zeroed) and compute the HMAC over
	// the zeroed-placeholder form, then splice it in.
	start, end, ok := usmAuthParamsRange(wholeMsg)
	if !ok {
		t.Fatalf("usmAuthParamsRange failed on freshly built packet")
	}
	if end-start != truncLen {
		t.Fatalf("authParams range %d..%d has len %d, want truncLen %d", start, end, end-start, truncLen)
	}
	mac := hmac.New(hashFn, authKey)
	mac.Write(wholeMsg)
	computed := mac.Sum(nil)
	if len(computed) > truncLen {
		computed = computed[:truncLen]
	}
	copy(wholeMsg[start:end], computed)

	return wholeMsg, start, end
}

// runVerify exercises the agent's verifyAuth path end-to-end for a packet
// built by buildV3AuthPacket.
func runVerify(t *testing.T, authProto, userName string, engineID []byte, longForm bool) bool {
	t.Helper()
	hashFn, hashLen := authHashFunc(authProto)
	authKey := passwordToKey("the-auth-password-1234", engineID, hashFn, hashLen)
	if authKey == nil {
		t.Fatalf("passwordToKey returned nil")
	}

	pkt, start, end := buildV3AuthPacket(t, authProto, userName, engineID, authKey, longForm)

	a := &Agent{
		engineID:   engineID,
		v3Users:    map[string]*usmUser{},
		lastPacket: pkt,
	}
	user := &usmUser{name: userName, authProto: authProto, authKey: authKey}
	a.v3Users[userName] = user

	// The received MAC is the authParams that were spliced into the packet.
	receivedMAC := append([]byte{}, pkt[start:end]...)
	return a.verifyAuth(user, receivedMAC)
}

// TestVerifyAuth_CollidingUsernameLength is the direct regression for #1710:
// a username whose byte length equals the HMAC truncation length used to make
// zeroAuthParams blank the username instead of authParams, breaking auth.
func TestVerifyAuth_CollidingUsernameLength(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x01, 0x02, 0x03} // 8 bytes, no collision

	cases := []struct {
		name      string
		authProto string
		userName  string // length == truncLen
	}{
		{"sha-12char-username", "sha", "abcdefghijkl"},                 // 12 chars, truncLen 12
		{"md5-12char-username", "md5", "abcdefghijkl"},                 // 12 chars, truncLen 12
		{"sha256-24char-username", "sha256", "abcdefghijklmnopqrstuvwx"}, // 24 chars, truncLen 24
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if len(c.userName) != authTruncLen(c.authProto) {
				t.Fatalf("test setup: username len %d != truncLen %d", len(c.userName), authTruncLen(c.authProto))
			}
			if !runVerify(t, c.authProto, c.userName, engineID, false) {
				t.Fatalf("verifyAuth failed for %s with %d-char username (regression #1710)", c.authProto, len(c.userName))
			}
		})
	}
}

// TestVerifyAuth_CollidingEngineIDLength covers the second #1710 trigger: a
// msgAuthoritativeEngineID of exactly truncLen bytes must not be mistaken for
// authParams.
func TestVerifyAuth_CollidingEngineIDLength(t *testing.T) {
	// 12-byte engineID collides with SHA-1/MD5 truncLen. Username is short.
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	if len(engineID) != authTruncLen("sha") {
		t.Fatalf("test setup: engineID len %d != truncLen %d", len(engineID), authTruncLen("sha"))
	}
	if !runVerify(t, "sha", "user", engineID, false) {
		t.Fatal("verifyAuth failed with a 12-byte engineID (regression #1710 engineID trigger)")
	}
}

// TestVerifyAuth_NonColliding is the control: an ordinary short username on
// the common path must still authenticate.
func TestVerifyAuth_NonColliding(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x09, 0x08, 0x07}
	for _, proto := range []string{"md5", "sha", "sha256"} {
		t.Run(proto, func(t *testing.T) {
			if !runVerify(t, proto, "admin", engineID, false) {
				t.Fatalf("verifyAuth failed for %s with ordinary username", proto)
			}
		})
	}
}

// TestVerifyAuth_LongFormLength forces multi-byte (long-form, >127) BER
// lengths on the wrapping TLVs so the locator's header-length accounting is
// exercised against the long-form path (Codex plan-review minor #3).
func TestVerifyAuth_LongFormLength(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xAA, 0xBB, 0xCC}
	if !runVerify(t, "sha256", "admin", engineID, true) {
		t.Fatal("verifyAuth failed with long-form BER lengths")
	}
}

// TestUsmAuthParamsRange_LocatesField checks that the locator returns the
// exact authParams range and that the username/engineID occupy different,
// non-overlapping ranges (so they cannot be confused even when their lengths
// match truncLen).
func TestUsmAuthParamsRange_LocatesField(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x01, 0x02, 0x03}
	authProto := "sha"
	truncLen := authTruncLen(authProto)
	hashFn, hashLen := authHashFunc(authProto)
	authKey := passwordToKey("pw", engineID, hashFn, hashLen)
	userName := "abcdefghijkl" // 12 chars == truncLen

	pkt, start, end := buildV3AuthPacket(t, authProto, userName, engineID, authKey, false)
	if end-start != truncLen {
		t.Fatalf("authParams range len %d, want %d", end-start, truncLen)
	}

	// The username bytes must appear before authParams at a distinct offset.
	unameIdx := bytes.Index(pkt, []byte(userName))
	if unameIdx < 0 {
		t.Fatal("username not found in packet")
	}
	if unameIdx >= start && unameIdx < end {
		t.Fatalf("username offset %d overlaps authParams range %d..%d", unameIdx, start, end)
	}
	if unameIdx >= start {
		t.Fatalf("username offset %d should precede authParams start %d", unameIdx, start)
	}

	// re-running the locator on a copy yields the same range (deterministic).
	cp := append([]byte{}, pkt...)
	s2, e2, ok := usmAuthParamsRange(cp)
	if !ok || s2 != start || e2 != end {
		t.Fatalf("locator non-deterministic: got %d..%d ok=%v, want %d..%d", s2, e2, ok, start, end)
	}
}

// TestZeroAuthParams_ZeroesOnlyAuthParams confirms zeroAuthParams blanks
// exactly the authParams value and leaves the username/engineID intact.
func TestZeroAuthParams_ZeroesOnlyAuthParams(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x01, 0x02, 0x03}
	authProto := "sha"
	hashFn, hashLen := authHashFunc(authProto)
	authKey := passwordToKey("pw", engineID, hashFn, hashLen)
	userName := "abcdefghijkl" // 12 chars == truncLen

	pkt, start, end := buildV3AuthPacket(t, authProto, userName, engineID, authKey, false)

	zeroAuthParams(pkt)

	// authParams range is all zero.
	for i := start; i < end; i++ {
		if pkt[i] != 0 {
			t.Fatalf("authParams byte %d not zeroed", i)
		}
	}
	// Username bytes survive.
	if !bytes.Contains(pkt, []byte(userName)) {
		t.Fatal("username was zeroed by zeroAuthParams (bug #1710)")
	}
	// engineID bytes survive.
	if !bytes.Contains(pkt, engineID) {
		t.Fatal("engineID was zeroed by zeroAuthParams (bug #1710)")
	}
}

// TestUsmAuthParamsRange_Malformed confirms fail-closed behavior: an
// unparseable packet returns ok=false (no-op zero), so verifyAuth fails.
func TestUsmAuthParamsRange_Malformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":            {},
		"not-a-sequence":   {0x02, 0x01, 0x03},
		"truncated-seq":    {0x30, 0x05, 0x02, 0x01},
		"seq-no-usm":       berEncodeTLV(tagSequence, berEncodeIntegerTLV(snmpVersion3)),
		"usm-too-few-flds": buildShortUSM(),
	}
	for name, pkt := range cases {
		t.Run(name, func(t *testing.T) {
			cp := append([]byte{}, pkt...)
			if _, _, ok := usmAuthParamsRange(cp); ok {
				t.Fatalf("expected ok=false for malformed packet %q", name)
			}
			// zeroAuthParams must be a no-op (no panic, no mutation).
			before := append([]byte{}, cp...)
			zeroAuthParams(cp)
			if !bytes.Equal(before, cp) {
				t.Fatalf("zeroAuthParams mutated bytes for malformed packet %q", name)
			}
		})
	}
}

// buildShortUSM builds a structurally valid v3 message whose USM sequence has
// only four fields (missing authParams + privParams), so the locator must
// fail closed.
func buildShortUSM() []byte {
	usmFields := berEncodeTLV(tagOctetString, []byte{0x01, 0x02})
	usmFields = append(usmFields, berEncodeIntegerTLV(1)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(2)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte("user"))...)
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	hdr := berEncodeIntegerTLV(42)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlagAuth})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	return berEncodeTLV(tagSequence, msgBody)
}
