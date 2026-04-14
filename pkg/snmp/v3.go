package snmp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
)

const (
	snmpVersion3 = 3 // version field for SNMPv3

	// USM security model (RFC 3414).
	usmSecurityModel = 3

	// SNMPv3 message flags.
	msgFlagAuth   = 0x01
	msgFlagPriv   = 0x02
	msgFlagReport = 0x04

	// Auth HMAC truncation lengths (RFC 3414, RFC 7860).
	hmacMD5Len    = 12
	hmacSHA1Len   = 12
	hmacSHA256Len = 24
)

// usmUser holds precomputed key material for a USM user.
type usmUser struct {
	name      string
	authProto string // "md5", "sha", "sha256"
	authKey   []byte
	privProto string // "des", "aes128"
	privKey   []byte
}

// initV3Users builds USM user entries from config, localizing passwords with the engine ID.
func (a *Agent) initV3Users() {
	if a.cfg == nil || len(a.cfg.V3Users) == 0 {
		return
	}
	a.v3Users = make(map[string]*usmUser, len(a.cfg.V3Users))
	for _, cu := range a.cfg.V3Users {
		u := &usmUser{name: cu.Name, authProto: cu.AuthProtocol, privProto: cu.PrivProtocol}
		hashFn, hashLen := authHashFunc(cu.AuthProtocol)
		if hashFn != nil && cu.AuthPassword != "" {
			u.authKey = passwordToKey(cu.AuthPassword, a.engineID, hashFn, hashLen)
		}
		if hashFn != nil && cu.PrivPassword != "" {
			u.privKey = passwordToKey(cu.PrivPassword, a.engineID, hashFn, hashLen)
		}
		a.v3Users[cu.Name] = u
	}
}

// authHashFunc returns the hash constructor and key length for an auth protocol.
func authHashFunc(proto string) (func() hash.Hash, int) {
	switch proto {
	case "md5":
		return md5.New, md5.Size
	case "sha":
		return sha1.New, sha1.Size
	case "sha256":
		return sha256.New, sha256.Size
	default:
		return nil, 0
	}
}

// authTruncLen returns the HMAC truncation length for an auth protocol.
func authTruncLen(proto string) int {
	switch proto {
	case "md5":
		return hmacMD5Len
	case "sha":
		return hmacSHA1Len
	case "sha256":
		return hmacSHA256Len
	default:
		return 12
	}
}

// passwordToKey derives a localized key from a password per RFC 3414 section A.2.
func passwordToKey(password string, engineID []byte, hashNew func() hash.Hash, hashLen int) []byte {
	h := hashNew()
	pw := []byte(password)
	pLen := len(pw)
	if pLen == 0 {
		return nil
	}
	// Step 1: Generate Ku by hashing password repeated to >= 1MB.
	count := 0
	for count < 1048576 {
		var buf [64]byte
		for i := range buf {
			buf[i] = pw[(count+i)%pLen]
		}
		h.Write(buf[:])
		count += 64
	}
	ku := h.Sum(nil)

	// Step 2: Localize Ku with engineID: Kul = HASH(Ku || engineID || Ku).
	h.Reset()
	h.Write(ku)
	h.Write(engineID)
	h.Write(ku)
	kul := h.Sum(nil)
	if len(kul) > hashLen {
		kul = kul[:hashLen]
	}
	return kul
}

// handleV3Packet processes an SNMPv3 message. Returns response bytes or nil.
func (a *Agent) handleV3Packet(msgBody []byte) []byte {
	// Decode HeaderData (SEQUENCE: msgID, msgMaxSize, msgFlags, msgSecurityModel).
	tag, headerBody, err := berDecodeHeader(msgBody)
	if err != nil || tag != tagSequence {
		slog.Debug("SNMPv3: invalid header SEQUENCE")
		return nil
	}

	msgID, rest, err := berDecodeInteger(headerBody)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode msgID")
		return nil
	}
	_, rest, err = berDecodeInteger(rest) // msgMaxSize
	if err != nil {
		slog.Debug("SNMPv3: failed to decode msgMaxSize")
		return nil
	}
	flagsBytes, rest, err := berDecodeOctetString(rest)
	if err != nil || len(flagsBytes) < 1 {
		slog.Debug("SNMPv3: failed to decode msgFlags")
		return nil
	}
	msgFlags := flagsBytes[0]

	secModel, _, err := berDecodeInteger(rest)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode securityModel")
		return nil
	}
	if secModel != usmSecurityModel {
		slog.Debug("SNMPv3: unsupported security model", "model", secModel)
		return nil
	}

	// Advance past the header in msgBody.
	headerTotalLen := berEncodedLen(msgBody)
	if headerTotalLen <= 0 || headerTotalLen >= len(msgBody) {
		slog.Debug("SNMPv3: header length error")
		return nil
	}
	afterHeader := msgBody[headerTotalLen:]

	// Decode USM Security Parameters (OCTET STRING wrapping a SEQUENCE).
	secParamsRaw, afterSecParams, err := berDecodeOctetString(afterHeader)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode security parameters")
		return nil
	}

	// Parse USM SEQUENCE inside the octet string.
	tag, usmBody, err := berDecodeHeader(secParamsRaw)
	if err != nil || tag != tagSequence {
		slog.Debug("SNMPv3: invalid USM SEQUENCE")
		return nil
	}

	// USM fields: engineID, engineBoots, engineTime, userName, authParams, privParams.
	_, usmRest, err := berDecodeOctetString(usmBody) // reqEngineID
	if err != nil {
		slog.Debug("SNMPv3: failed to decode engineID")
		return nil
	}
	_, usmRest, err = berDecodeInteger(usmRest) // engineBoots
	if err != nil {
		slog.Debug("SNMPv3: failed to decode engineBoots")
		return nil
	}
	_, usmRest, err = berDecodeInteger(usmRest) // engineTime
	if err != nil {
		slog.Debug("SNMPv3: failed to decode engineTime")
		return nil
	}
	userNameBytes, usmRest, err := berDecodeOctetString(usmRest)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode userName")
		return nil
	}
	authParams, usmRest, err := berDecodeOctetString(usmRest)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode authParams")
		return nil
	}
	privParams, _, err := berDecodeOctetString(usmRest)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode privParams")
		return nil
	}

	userName := string(userNameBytes)

	// Discovery: empty userName means engine ID discovery.
	if userName == "" {
		return a.buildV3Discovery(msgID)
	}

	// Lookup user.
	user := a.v3Users[userName]
	if user == nil {
		slog.Debug("SNMPv3: unknown user", "user", userName)
		return nil
	}

	// Verify authentication if required.
	if msgFlags&msgFlagAuth != 0 {
		if user.authKey == nil {
			slog.Debug("SNMPv3: user has no auth key", "user", userName)
			return nil
		}
		if !a.verifyAuth(user, authParams) {
			slog.Debug("SNMPv3: authentication failed", "user", userName)
			return nil
		}
	}

	// Decode scoped PDU (possibly encrypted).
	var scopedPDUBody []byte
	if msgFlags&msgFlagPriv != 0 {
		encData, _, err := berDecodeOctetString(afterSecParams)
		if err != nil {
			slog.Debug("SNMPv3: failed to decode encrypted PDU")
			return nil
		}
		decrypted := a.decryptPDU(user, privParams, encData)
		if decrypted == nil {
			slog.Debug("SNMPv3: decryption failed", "user", userName)
			return nil
		}
		// Decrypted data is a scopedPDU SEQUENCE.
		tag, body, err := berDecodeHeader(decrypted)
		if err != nil || tag != tagSequence {
			slog.Debug("SNMPv3: invalid decrypted scopedPDU")
			return nil
		}
		scopedPDUBody = body
	} else {
		tag, body, err := berDecodeHeader(afterSecParams)
		if err != nil || tag != tagSequence {
			slog.Debug("SNMPv3: invalid scopedPDU")
			return nil
		}
		scopedPDUBody = body
	}

	// Parse scopedPDU: contextEngineID, contextName, PDU.
	_, scopedRest, err := berDecodeOctetString(scopedPDUBody) // contextEngineID
	if err != nil {
		slog.Debug("SNMPv3: failed to decode contextEngineID")
		return nil
	}
	_, scopedRest, err = berDecodeOctetString(scopedRest) // contextName
	if err != nil {
		slog.Debug("SNMPv3: failed to decode contextName")
		return nil
	}

	// Decode PDU.
	pduTag, pduBody, err := berDecodeHeader(scopedRest)
	if err != nil {
		slog.Debug("SNMPv3: failed to decode PDU")
		return nil
	}

	var respVarbinds []varbind
	var requestID int

	switch pduTag {
	case pduGetRequest:
		var oids [][]int
		requestID, _, _, oids, err = decodePDUFields(pduBody)
		if err != nil {
			return nil
		}
		for _, oid := range oids {
			val, valTag := a.getOIDValue(oid)
			if val == nil {
				respVarbinds = append(respVarbinds, varbind{oid: oid, tag: tagNoSuchInstance})
			} else {
				respVarbinds = append(respVarbinds, varbind{oid: oid, tag: valTag, value: val})
			}
		}

	case pduGetNextRequest:
		var oids [][]int
		requestID, _, _, oids, err = decodePDUFields(pduBody)
		if err != nil {
			return nil
		}
		for _, oid := range oids {
			nextOID := a.findNextOID(oid)
			if nextOID == nil {
				respVarbinds = append(respVarbinds, varbind{oid: oid, tag: tagEndOfMibView})
			} else {
				val, valTag := a.getOIDValue(nextOID)
				respVarbinds = append(respVarbinds, varbind{oid: nextOID, tag: valTag, value: val})
			}
		}

	case pduGetBulkRequest:
		var oids [][]int
		var nonRepeaters, maxRepetitions int
		requestID, nonRepeaters, maxRepetitions, oids, err = decodePDUFields(pduBody)
		if err != nil {
			return nil
		}
		if nonRepeaters < 0 {
			nonRepeaters = 0
		}
		if maxRepetitions < 0 {
			maxRepetitions = 0
		}
		if maxRepetitions > 100 {
			maxRepetitions = 100
		}
		for i := 0; i < nonRepeaters && i < len(oids); i++ {
			nextOID := a.findNextOID(oids[i])
			if nextOID == nil {
				respVarbinds = append(respVarbinds, varbind{oid: oids[i], tag: tagEndOfMibView})
			} else {
				val, valTag := a.getOIDValue(nextOID)
				respVarbinds = append(respVarbinds, varbind{oid: nextOID, tag: valTag, value: val})
			}
		}
		for i := nonRepeaters; i < len(oids); i++ {
			currentOID := oids[i]
			for j := 0; j < maxRepetitions; j++ {
				nextOID := a.findNextOID(currentOID)
				if nextOID == nil {
					respVarbinds = append(respVarbinds, varbind{oid: currentOID, tag: tagEndOfMibView})
					break
				}
				val, valTag := a.getOIDValue(nextOID)
				respVarbinds = append(respVarbinds, varbind{oid: nextOID, tag: valTag, value: val})
				currentOID = nextOID
			}
		}

	default:
		slog.Debug("SNMPv3: unsupported PDU type", "type", pduTag)
		return nil
	}

	return a.buildV3Response(msgID, msgFlags, user, requestID, errNoError, 0, respVarbinds)
}

// verifyAuth checks the HMAC authentication of a v3 message.
func (a *Agent) verifyAuth(user *usmUser, receivedMAC []byte) bool {
	hashFn, _ := authHashFunc(user.authProto)
	if hashFn == nil {
		return false
	}
	truncLen := authTruncLen(user.authProto)
	if len(receivedMAC) != truncLen {
		return false
	}

	// Build a copy of the whole packet with authParams zeroed.
	pkt := make([]byte, len(a.lastPacket))
	copy(pkt, a.lastPacket)
	zeroAuthParams(pkt, truncLen)

	mac := hmac.New(hashFn, user.authKey)
	mac.Write(pkt)
	computed := mac.Sum(nil)
	if len(computed) > truncLen {
		computed = computed[:truncLen]
	}
	return hmac.Equal(computed, receivedMAC)
}

// zeroAuthParams finds the auth params OCTET STRING in a raw SNMPv3 packet and zeroes it.
func zeroAuthParams(pkt []byte, truncLen int) {
	for i := 0; i < len(pkt)-truncLen-1; i++ {
		if pkt[i] == tagOctetString {
			length, lenBytes, err := berDecodeLength(pkt[i+1:])
			if err != nil {
				continue
			}
			if length == truncLen {
				start := i + 1 + lenBytes
				if start+truncLen <= len(pkt) {
					nonZero := false
					for j := start; j < start+truncLen; j++ {
						if pkt[j] != 0 {
							nonZero = true
							break
						}
					}
					if nonZero {
						for j := start; j < start+truncLen; j++ {
							pkt[j] = 0
						}
						return
					}
				}
			}
		}
	}
}

// decryptPDU decrypts an encrypted scopedPDU using the user's privacy key.
func (a *Agent) decryptPDU(user *usmUser, privParams, encData []byte) []byte {
	if user.privKey == nil {
		return nil
	}
	switch user.privProto {
	case "des":
		return decryptDES(user.privKey, privParams, encData)
	case "aes128":
		return decryptAES128(user.privKey, privParams, encData, a.engineBoots, a.engineTime())
	default:
		return nil
	}
}

// decryptDES decrypts data using DES-CBC per RFC 3414 section 8.
func decryptDES(privKey, privParams, data []byte) []byte {
	if len(privKey) < 16 || len(privParams) != 8 || len(data) == 0 || len(data)%8 != 0 {
		return nil
	}
	desKey := privKey[:8]
	preIV := privKey[8:16]
	iv := make([]byte, 8)
	for i := range iv {
		iv[i] = preIV[i] ^ privParams[i]
	}
	block, err := des.NewCipher(desKey)
	if err != nil {
		return nil
	}
	plaintext := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, data)
	return plaintext
}

// decryptAES128 decrypts data using AES-128-CFB per RFC 3826.
func decryptAES128(privKey, privParams, data []byte, boots, time int) []byte {
	if len(privKey) < 16 || len(privParams) != 8 || len(data) == 0 {
		return nil
	}
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:4], uint32(boots))
	binary.BigEndian.PutUint32(iv[4:8], uint32(time))
	copy(iv[8:16], privParams)
	block, err := aes.NewCipher(privKey[:16])
	if err != nil {
		return nil
	}
	plaintext := make([]byte, len(data))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plaintext, data)
	return plaintext
}

// encryptPDU encrypts a scopedPDU using the user's privacy key.
func (a *Agent) encryptPDU(user *usmUser, scopedPDU []byte) (encrypted, privParams []byte) {
	if user.privKey == nil {
		return nil, nil
	}
	switch user.privProto {
	case "des":
		return encryptDES(user.privKey, scopedPDU)
	case "aes128":
		return encryptAES128(user.privKey, scopedPDU, a.engineBoots, a.engineTime())
	default:
		return nil, nil
	}
}

// encryptDES encrypts data using DES-CBC per RFC 3414 section 8.
func encryptDES(privKey, data []byte) ([]byte, []byte) {
	if len(privKey) < 16 {
		return nil, nil
	}
	desKey := privKey[:8]
	preIV := privKey[8:16]
	privParams := make([]byte, 8)
	rand.Read(privParams)
	iv := make([]byte, 8)
	for i := range iv {
		iv[i] = preIV[i] ^ privParams[i]
	}
	// Pad to DES block size.
	if pad := 8 - (len(data) % 8); pad < 8 {
		data = append(data, make([]byte, pad)...)
	}
	block, err := des.NewCipher(desKey)
	if err != nil {
		return nil, nil
	}
	encrypted := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, data)
	return encrypted, privParams
}

// encryptAES128 encrypts data using AES-128-CFB per RFC 3826.
func encryptAES128(privKey, data []byte, boots, time int) ([]byte, []byte) {
	if len(privKey) < 16 {
		return nil, nil
	}
	privParams := make([]byte, 8)
	rand.Read(privParams)
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:4], uint32(boots))
	binary.BigEndian.PutUint32(iv[4:8], uint32(time))
	copy(iv[8:16], privParams)
	block, err := aes.NewCipher(privKey[:16])
	if err != nil {
		return nil, nil
	}
	encrypted := make([]byte, len(data))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(encrypted, data)
	return encrypted, privParams
}

// computeAuth computes the HMAC for a v3 message (with auth params zeroed in the message).
func computeAuth(user *usmUser, wholeMsg []byte) []byte {
	hashFn, _ := authHashFunc(user.authProto)
	if hashFn == nil {
		return nil
	}
	truncLen := authTruncLen(user.authProto)
	mac := hmac.New(hashFn, user.authKey)
	mac.Write(wholeMsg)
	result := mac.Sum(nil)
	if len(result) > truncLen {
		result = result[:truncLen]
	}
	return result
}

// buildV3Discovery builds a discovery response (report) with our engine ID.
func (a *Agent) buildV3Discovery(msgID int) []byte {
	// USM security parameters.
	usmFields := berEncodeTLV(tagOctetString, a.engineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(a.engineBoots)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(a.engineTime())...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // userName
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // authParams
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // privParams
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	// Header.
	hdr := berEncodeIntegerTLV(msgID)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{msgFlagReport})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	// Report PDU with usmStatsUnknownEngineIDs (1.3.6.1.6.3.15.1.1.4.0).
	reportOID := []int{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0}
	vb := berEncodeTLV(tagObjectIdentifier, berEncodeOID(reportOID))
	vb = append(vb, berEncodeTLV(tagCounter32, berEncodeCounter32(0))...)
	vbList := berEncodeTLV(tagSequence, berEncodeTLV(tagSequence, vb))
	pduBody := berEncodeIntegerTLV(0)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbList...)
	reportPDU := berEncodeTLV(0xa8, pduBody) // Report PDU tag

	scopedBody := berEncodeTLV(tagOctetString, a.engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, nil)...)
	scopedBody = append(scopedBody, reportPDU...)
	scopedPDU := berEncodeTLV(tagSequence, scopedBody)

	// Assemble full message.
	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	msgBody = append(msgBody, scopedPDU...)
	return berEncodeTLV(tagSequence, msgBody)
}

// buildV3Response builds an authenticated (and optionally encrypted) SNMPv3 response.
func (a *Agent) buildV3Response(msgID int, reqFlags byte, user *usmUser,
	requestID, errorStatus, errorIndex int, vbs []varbind) []byte {

	// Build varbind list.
	var vbListBytes []byte
	for _, vb := range vbs {
		oidBytes := berEncodeTLV(tagObjectIdentifier, berEncodeOID(vb.oid))
		var valBytes []byte
		if vb.tag == tagNoSuchObject || vb.tag == tagNoSuchInstance || vb.tag == tagEndOfMibView {
			valBytes = berEncodeTLV(vb.tag, nil)
		} else {
			valBytes = berEncodeValue(vb.tag, vb.value)
		}
		vbListBytes = append(vbListBytes, berEncodeTLV(tagSequence, append(oidBytes, valBytes...))...)
	}
	vbListEncoded := berEncodeTLV(tagSequence, vbListBytes)

	// Build response PDU.
	pduBody := berEncodeIntegerTLV(requestID)
	pduBody = append(pduBody, berEncodeIntegerTLV(errorStatus)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(errorIndex)...)
	pduBody = append(pduBody, vbListEncoded...)
	responsePDU := berEncodeTLV(pduGetResponse, pduBody)

	// Build scopedPDU.
	scopedBody := berEncodeTLV(tagOctetString, a.engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, nil)...) // contextName
	scopedBody = append(scopedBody, responsePDU...)
	scopedPDU := berEncodeTLV(tagSequence, scopedBody)

	// Determine response flags.
	respFlags := reqFlags & (msgFlagAuth | msgFlagPriv)

	// Handle encryption.
	var scopedPDUEncoded []byte
	var privParamsVal []byte
	if respFlags&msgFlagPriv != 0 && user.privKey != nil {
		enc, pp := a.encryptPDU(user, scopedPDU)
		if enc != nil {
			scopedPDUEncoded = berEncodeTLV(tagOctetString, enc)
			privParamsVal = pp
		} else {
			respFlags &^= msgFlagPriv
			scopedPDUEncoded = scopedPDU
		}
	} else {
		respFlags &^= msgFlagPriv
		scopedPDUEncoded = scopedPDU
	}

	// Auth params placeholder.
	truncLen := authTruncLen(user.authProto)
	var authPlaceholder []byte
	if respFlags&msgFlagAuth != 0 && user.authKey != nil {
		authPlaceholder = make([]byte, truncLen)
	}

	// USM security parameters.
	usmFields := berEncodeTLV(tagOctetString, a.engineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(a.engineBoots)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(a.engineTime())...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte(user.name))...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, authPlaceholder)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, privParamsVal)...)
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	// Header.
	hdr := berEncodeIntegerTLV(msgID)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{respFlags})...)
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	// Assemble full message.
	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	msgBody = append(msgBody, scopedPDUEncoded...)
	wholeMsg := berEncodeTLV(tagSequence, msgBody)

	// Compute and insert auth HMAC.
	if respFlags&msgFlagAuth != 0 && user.authKey != nil {
		// wholeMsg currently has zeroed auth placeholder — compute HMAC over it.
		authMAC := computeAuth(user, wholeMsg)
		if authMAC != nil {
			insertAuthMAC(wholeMsg, authMAC, truncLen)
		}
	}

	return wholeMsg
}

// insertAuthMAC finds the zeroed auth placeholder in a packet and replaces it with the HMAC.
func insertAuthMAC(pkt, authMAC []byte, truncLen int) {
	for i := 0; i < len(pkt)-truncLen; i++ {
		if pkt[i] == tagOctetString {
			length, lenBytes, err := berDecodeLength(pkt[i+1:])
			if err != nil {
				continue
			}
			if length == truncLen {
				start := i + 1 + lenBytes
				if start+truncLen <= len(pkt) {
					allZero := true
					for j := start; j < start+truncLen; j++ {
						if pkt[j] != 0 {
							allZero = false
							break
						}
					}
					if allZero {
						copy(pkt[start:start+truncLen], authMAC)
						return
					}
				}
			}
		}
	}
}

// V3UserInfo returns user info for display (without passwords).
func V3UserInfo(users map[string]*config.SNMPv3User) []V3UserDisplay {
	var result []V3UserDisplay
	for _, u := range users {
		result = append(result, V3UserDisplay{
			Name:      u.Name,
			AuthProto: u.AuthProtocol,
			PrivProto: u.PrivProtocol,
		})
	}
	return result
}

// V3UserDisplay holds user info for display purposes.
type V3UserDisplay struct {
	Name      string
	AuthProto string
	PrivProto string
}
