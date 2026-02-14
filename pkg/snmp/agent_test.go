package snmp

import (
	"crypto/md5"
	"crypto/sha1"
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

var (
	md5New  = md5.New
	md5Size = md5.Size
	sha1New = sha1.New
	sha1Size = sha1.Size
)

// --- BER encoding tests ---

func TestBerEncodeLength_Short(t *testing.T) {
	got := berEncodeLength(5)
	if len(got) != 1 || got[0] != 5 {
		t.Errorf("berEncodeLength(5) = %v, want [5]", got)
	}
}

func TestBerEncodeLength_OneByte(t *testing.T) {
	got := berEncodeLength(127)
	if len(got) != 1 || got[0] != 127 {
		t.Errorf("berEncodeLength(127) = %v, want [127]", got)
	}
}

func TestBerEncodeLength_TwoBytes(t *testing.T) {
	got := berEncodeLength(200)
	// 0x81, 0xC8 (200)
	if len(got) != 2 || got[0] != 0x81 || got[1] != 200 {
		t.Errorf("berEncodeLength(200) = %v, want [0x81, 200]", got)
	}
}

func TestBerEncodeIntegerValue(t *testing.T) {
	tests := []struct {
		val  int
		want []byte
	}{
		{0, []byte{0}},
		{1, []byte{1}},
		{127, []byte{127}},
		{128, []byte{0, 128}}, // high bit set needs leading zero
		{256, []byte{1, 0}},
	}
	for _, tt := range tests {
		got := berEncodeIntegerValue(tt.val)
		if !bytesEqual(got, tt.want) {
			t.Errorf("berEncodeIntegerValue(%d) = %v, want %v", tt.val, got, tt.want)
		}
	}
}

func TestBerEncodeOID(t *testing.T) {
	// 1.3.6.1.2.1.1.1.0 => first byte = 1*40+3 = 43, then 6,1,2,1,1,1,0
	got := berEncodeOID([]int{1, 3, 6, 1, 2, 1, 1, 1, 0})
	want := []byte{43, 6, 1, 2, 1, 1, 1, 0}
	if !bytesEqual(got, want) {
		t.Errorf("berEncodeOID(sysDescr) = %v, want %v", got, want)
	}
}

func TestBerEncodeOID_Short(t *testing.T) {
	got := berEncodeOID([]int{1})
	if got != nil {
		t.Errorf("berEncodeOID with < 2 components should return nil, got %v", got)
	}
}

func TestBerEncodeSubID(t *testing.T) {
	tests := []struct {
		val  int
		want []byte
	}{
		{0, []byte{0}},
		{127, []byte{127}},
		{128, []byte{0x81, 0x00}},
		{16383, []byte{0xff, 0x7f}},
	}
	for _, tt := range tests {
		got := berEncodeSubID(tt.val)
		if !bytesEqual(got, tt.want) {
			t.Errorf("berEncodeSubID(%d) = %v, want %v", tt.val, got, tt.want)
		}
	}
}

func TestBerEncodeTimeTicks(t *testing.T) {
	got := berEncodeTimeTicks(100)
	// 100 = 0x00000064, strip leading zeros → 0x64
	if len(got) != 1 || got[0] != 0x64 {
		t.Errorf("berEncodeTimeTicks(100) = %v, want [0x64]", got)
	}
}

func TestBerEncodeTimeTicks_Large(t *testing.T) {
	got := berEncodeTimeTicks(360000) // 1 hour in hundredths
	// 360000 = 0x00057E40
	if len(got) != 3 { // should be [0x05, 0x7E, 0x40]
		t.Errorf("berEncodeTimeTicks(360000) = %v, expected 3 bytes", got)
	}
}

// --- BER decoding tests ---

func TestBerDecodeLength_Short(t *testing.T) {
	length, consumed, err := berDecodeLength([]byte{42})
	if err != nil || length != 42 || consumed != 1 {
		t.Errorf("got length=%d, consumed=%d, err=%v", length, consumed, err)
	}
}

func TestBerDecodeLength_Long(t *testing.T) {
	// 0x81 0xC8 = 200 bytes
	length, consumed, err := berDecodeLength([]byte{0x81, 0xC8})
	if err != nil || length != 200 || consumed != 2 {
		t.Errorf("got length=%d, consumed=%d, err=%v", length, consumed, err)
	}
}

func TestBerDecodeInteger(t *testing.T) {
	// Integer 42: tag=0x02, length=0x01, value=0x2A
	data := []byte{0x02, 0x01, 0x2A, 0xFF} // trailing byte
	val, rest, err := berDecodeInteger(data)
	if err != nil || val != 42 {
		t.Errorf("berDecodeInteger: val=%d, err=%v", val, err)
	}
	if len(rest) != 1 || rest[0] != 0xFF {
		t.Errorf("remaining bytes wrong: %v", rest)
	}
}

func TestBerDecodeInteger_Zero(t *testing.T) {
	data := []byte{0x02, 0x01, 0x00}
	val, _, err := berDecodeInteger(data)
	if err != nil || val != 0 {
		t.Errorf("berDecodeInteger(0): val=%d, err=%v", val, err)
	}
}

func TestBerDecodeOctetString(t *testing.T) {
	data := []byte{0x04, 0x05, 'h', 'e', 'l', 'l', 'o', 0xFF}
	val, rest, err := berDecodeOctetString(data)
	if err != nil || string(val) != "hello" {
		t.Errorf("berDecodeOctetString: val=%q, err=%v", val, err)
	}
	if len(rest) != 1 || rest[0] != 0xFF {
		t.Errorf("remaining bytes wrong: %v", rest)
	}
}

func TestBerDecodeOID(t *testing.T) {
	// 1.3.6.1.2.1.1.1.0 => [43, 6, 1, 2, 1, 1, 1, 0]
	raw := []byte{43, 6, 1, 2, 1, 1, 1, 0}
	oid, err := berDecodeOID(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	if !intsEqual(oid, want) {
		t.Errorf("berDecodeOID = %v, want %v", oid, want)
	}
}

func TestBerDecodeOID_Empty(t *testing.T) {
	_, err := berDecodeOID(nil)
	if err == nil {
		t.Error("expected error for empty OID")
	}
}

// --- OID comparison tests ---

func TestOIDEqual(t *testing.T) {
	if !oidEqual([]int{1, 3, 6}, []int{1, 3, 6}) {
		t.Error("same OIDs should be equal")
	}
	if oidEqual([]int{1, 3, 6}, []int{1, 3, 7}) {
		t.Error("different OIDs should not be equal")
	}
	if oidEqual([]int{1, 3}, []int{1, 3, 6}) {
		t.Error("different length OIDs should not be equal")
	}
}

func TestOIDCompare(t *testing.T) {
	tests := []struct {
		a, b []int
		want int
	}{
		{[]int{1, 3, 6}, []int{1, 3, 6}, 0},
		{[]int{1, 3, 5}, []int{1, 3, 6}, -1},
		{[]int{1, 3, 7}, []int{1, 3, 6}, 1},
		{[]int{1, 3}, []int{1, 3, 6}, -1},
		{[]int{1, 3, 6, 1}, []int{1, 3, 6}, 1},
	}
	for _, tt := range tests {
		if got := oidCompare(tt.a, tt.b); got != tt.want {
			t.Errorf("oidCompare(%v, %v) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// --- Agent functional tests ---

func TestFindNextOID(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})

	// Asking for next after sysDescr should return sysObjectID
	next := a.findNextOID(oidSysDescr)
	if !oidEqual(next, oidSysObjectID) {
		t.Errorf("next after sysDescr should be sysObjectID, got %v", next)
	}

	// Asking for next after sysLocation should return ifNumber
	next = a.findNextOID(oidSysLocation)
	if !oidEqual(next, oidIfNumber) {
		t.Errorf("next after sysLocation should be ifNumber, got %v", next)
	}

	// With no ifDataFn, next after ifNumber should be nil (no ifTable entries)
	next = a.findNextOID(oidIfNumber)
	if next != nil {
		t.Errorf("next after ifNumber with no interfaces should be nil, got %v", next)
	}

	// Asking for next with a prefix before all OIDs should return sysDescr
	next = a.findNextOID([]int{1, 3, 6, 1, 2, 1, 0})
	if !oidEqual(next, oidSysDescr) {
		t.Errorf("next before tree should be sysDescr, got %v", next)
	}
}

func TestIsValidCommunity(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})

	if !a.isValidCommunity("public") {
		t.Error("public should be valid")
	}
	if a.isValidCommunity("private") {
		t.Error("private should be invalid")
	}
}

func TestIsValidCommunity_NilConfig(t *testing.T) {
	a := NewAgent(nil)
	if a.isValidCommunity("public") {
		t.Error("nil config should reject all communities")
	}
}

func TestGetOIDValue_SysDescr(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{Description: "my firewall"})
	val, tag := a.getOIDValue(oidSysDescr)
	if tag != tagOctetString || string(val) != "my firewall" {
		t.Errorf("sysDescr: tag=%d val=%q", tag, val)
	}
}

func TestGetOIDValue_SysDescr_Default(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	val, tag := a.getOIDValue(oidSysDescr)
	if tag != tagOctetString || string(val) != "bpfrx eBPF firewall" {
		t.Errorf("sysDescr default: tag=%d val=%q", tag, val)
	}
}

func TestGetOIDValue_SysContact(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{Contact: "admin@example.com"})
	val, tag := a.getOIDValue(oidSysContact)
	if tag != tagOctetString || string(val) != "admin@example.com" {
		t.Errorf("sysContact: tag=%d val=%q", tag, val)
	}
}

func TestGetOIDValue_SysLocation(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{Location: "datacenter-1"})
	val, tag := a.getOIDValue(oidSysLocation)
	if tag != tagOctetString || string(val) != "datacenter-1" {
		t.Errorf("sysLocation: tag=%d val=%q", tag, val)
	}
}

func TestGetOIDValue_SysUpTime(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	val, tag := a.getOIDValue(oidSysUpTime)
	if tag != tagTimeTicks || val == nil {
		t.Error("sysUpTime should return TimeTicks")
	}
}

func TestGetOIDValue_Unknown(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	val, _ := a.getOIDValue([]int{1, 3, 6, 1, 2, 1, 99, 0})
	if val != nil {
		t.Error("unknown OID should return nil")
	}
}

func TestGetOIDValue_IfNumber(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(func() []IfData {
		return []IfData{
			{IfIndex: 2, IfDescr: "trust0"},
			{IfIndex: 3, IfDescr: "untrust0"},
		}
	})
	val, tag := a.getOIDValue(oidIfNumber)
	if tag != tagInteger {
		t.Errorf("ifNumber tag = %d, want INTEGER", tag)
	}
	// Decode the integer value
	encoded := berEncodeIntegerTLV(2)
	decoded, _, _ := berDecodeInteger(encoded)
	if decoded != 2 {
		t.Errorf("ifNumber value decode check failed: got %d", decoded)
	}
	_ = val
}

func TestIfTableWalk(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	a.SetIfDataFn(func() []IfData {
		return []IfData{
			{IfIndex: 2, IfDescr: "trust0", IfType: 6, IfMtu: 1500, AdminStatus: 1, OperStatus: 1},
			{IfIndex: 3, IfDescr: "untrust0", IfType: 6, IfMtu: 1500, AdminStatus: 1, OperStatus: 2},
		}
	})

	// Walking from ifNumber should reach ifTable column 1, ifIndex 2
	next := a.findNextOID(oidIfNumber)
	// Should be 1.3.6.1.2.1.2.2.1.1.2 (ifIndex.2)
	wantPrefix := append([]int{}, oidIfTablePrefix...)
	wantFirst := append(wantPrefix, 1, 2)
	if !oidEqual(next, wantFirst) {
		t.Errorf("first ifTable entry should be ifIndex.2, got %v", next)
	}

	// Get value of ifDescr.2
	ifDescrOID := append(append([]int{}, oidIfTablePrefix...), 2, 2)
	val, tag := a.getOIDValue(ifDescrOID)
	if tag != tagOctetString || string(val) != "trust0" {
		t.Errorf("ifDescr.2 = %q (tag %d), want 'trust0'", val, tag)
	}

	// Get value of ifOperStatus.3 (untrust0 is down)
	ifOperOID := append(append([]int{}, oidIfTablePrefix...), 8, 3)
	val, tag = a.getOIDValue(ifOperOID)
	if tag != tagInteger {
		t.Errorf("ifOperStatus.3 tag = %d, want INTEGER", tag)
	}
	// Value 2 = down
	decoded, _, _ := berDecodeInteger(berEncodeTLV(tagInteger, val))
	if decoded != 2 {
		t.Errorf("ifOperStatus.3 = %d, want 2 (down)", decoded)
	}
}

func TestCounter32Encoding(t *testing.T) {
	// 0 should encode to [0]
	got := berEncodeCounter32(0)
	if len(got) != 1 || got[0] != 0 {
		t.Errorf("Counter32(0) = %v, want [0]", got)
	}
	// 255 should encode to [0, 255] (high bit set, needs leading zero)
	got = berEncodeCounter32(255)
	if len(got) != 2 || got[0] != 0 || got[1] != 255 {
		t.Errorf("Counter32(255) = %v, want [0, 255]", got)
	}
	// 100 should encode to [100]
	got = berEncodeCounter32(100)
	if len(got) != 1 || got[0] != 100 {
		t.Errorf("Counter32(100) = %v, want [100]", got)
	}
}

func TestBerEncodedLen(t *testing.T) {
	// A simple SEQUENCE: tag=0x30, length=0x03, value=3 bytes
	data := []byte{0x30, 0x03, 0x01, 0x02, 0x03, 0xFF} // trailing byte
	got := berEncodedLen(data)
	if got != 5 { // 1 (tag) + 1 (length) + 3 (value) = 5
		t.Errorf("berEncodedLen = %d, want 5", got)
	}
}

func TestBerDecodeHeader(t *testing.T) {
	// SEQUENCE of 3 bytes
	data := []byte{0x30, 0x03, 0xAA, 0xBB, 0xCC}
	tag, body, err := berDecodeHeader(data)
	if err != nil || tag != 0x30 || len(body) != 3 {
		t.Errorf("tag=%d, body=%v, err=%v", tag, body, err)
	}
}

// --- Roundtrip test: encode + decode ---

func TestBerOIDRoundtrip(t *testing.T) {
	original := []int{1, 3, 6, 1, 4, 1, 99999, 1}
	encoded := berEncodeOID(original)
	decoded, err := berDecodeOID(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !intsEqual(original, decoded) {
		t.Errorf("roundtrip failed: %v -> %v", original, decoded)
	}
}

func TestBerIntegerRoundtrip(t *testing.T) {
	for _, val := range []int{0, 1, 127, 128, 255, 256, 65535, 100000} {
		encoded := berEncodeIntegerTLV(val)
		decoded, _, err := berDecodeInteger(encoded)
		if err != nil {
			t.Errorf("decode error for %d: %v", val, err)
			continue
		}
		if decoded != val {
			t.Errorf("roundtrip: %d -> %d", val, decoded)
		}
	}
}

// --- helpers ---

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func intsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- SNMPv3 USM tests ---

func TestPasswordToKey_MD5(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x01, 0x86, 0xa3, 0x04, 't', 'e', 's', 't'}
	key := passwordToKey("maplesyrup", engineID, md5New, md5Size)
	if key == nil {
		t.Fatal("passwordToKey returned nil")
	}
	if len(key) != md5Size {
		t.Errorf("key length = %d, want %d", len(key), md5Size)
	}
}

func TestPasswordToKey_SHA(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x01, 0x86, 0xa3, 0x04, 't', 'e', 's', 't'}
	key := passwordToKey("testpassword", engineID, sha1New, sha1Size)
	if key == nil {
		t.Fatal("passwordToKey returned nil")
	}
	if len(key) != sha1Size {
		t.Errorf("key length = %d, want %d", len(key), sha1Size)
	}
}

func TestPasswordToKey_EmptyPassword(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x01, 0x86, 0xa3}
	key := passwordToKey("", engineID, md5New, md5Size)
	if key != nil {
		t.Error("empty password should return nil")
	}
}

func TestInitV3Users(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		V3Users: map[string]*config.SNMPv3User{
			"admin": {
				Name:         "admin",
				AuthProtocol: "sha",
				AuthPassword: "authpass123",
				PrivProtocol: "aes128",
				PrivPassword: "privpass456",
			},
		},
	})
	if len(a.v3Users) != 1 {
		t.Fatalf("v3Users count = %d, want 1", len(a.v3Users))
	}
	u := a.v3Users["admin"]
	if u == nil {
		t.Fatal("admin user not found")
	}
	if u.authProto != "sha" {
		t.Errorf("authProto = %q, want sha", u.authProto)
	}
	if u.authKey == nil {
		t.Error("authKey is nil")
	}
	if u.privProto != "aes128" {
		t.Errorf("privProto = %q, want aes128", u.privProto)
	}
	if u.privKey == nil {
		t.Error("privKey is nil")
	}
}

func TestInitV3Users_NilConfig(t *testing.T) {
	a := NewAgent(nil)
	if a.v3Users != nil {
		t.Error("nil config should leave v3Users nil")
	}
}

func TestV3Discovery(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		V3Users: map[string]*config.SNMPv3User{
			"test": {Name: "test", AuthProtocol: "sha", AuthPassword: "testpass"},
		},
	})
	resp := a.buildV3Discovery(42)
	if resp == nil {
		t.Fatal("discovery response is nil")
	}
	// Should be a valid BER SEQUENCE.
	tag, _, err := berDecodeHeader(resp)
	if err != nil || tag != tagSequence {
		t.Errorf("discovery response: tag=%d, err=%v", tag, err)
	}
}

func TestV3UserDisplay(t *testing.T) {
	users := map[string]*config.SNMPv3User{
		"admin": {Name: "admin", AuthProtocol: "sha256", PrivProtocol: "aes128"},
		"guest": {Name: "guest", AuthProtocol: "md5"},
	}
	info := V3UserInfo(users)
	if len(info) != 2 {
		t.Fatalf("V3UserInfo count = %d, want 2", len(info))
	}
}

func TestEngineIDGeneration(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{})
	if a.engineID == nil {
		t.Fatal("engineID is nil")
	}
	if len(a.engineID) < 6 {
		t.Errorf("engineID too short: %d bytes", len(a.engineID))
	}
	// First 5 bytes should be fixed prefix, 6th byte should be 0x04 (text format).
	if a.engineID[5] != 0x04 {
		t.Errorf("engineID format byte = %d, want 4", a.engineID[5])
	}
}

func TestDESEncryptDecrypt(t *testing.T) {
	// Need a 16-byte key (8 for DES + 8 for preIV).
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	plaintext := []byte("hello world test") // 16 bytes (multiple of 8)
	enc, pp := encryptDES(key, plaintext)
	if enc == nil {
		t.Fatal("encryptDES returned nil")
	}
	dec := decryptDES(key, pp, enc)
	if dec == nil {
		t.Fatal("decryptDES returned nil")
	}
	if !bytesEqual(dec, plaintext) {
		t.Errorf("DES roundtrip failed: got %v, want %v", dec, plaintext)
	}
}

func TestAES128EncryptDecrypt(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1)
	}
	plaintext := []byte("test data for aes encryption roundtrip")
	enc, pp := encryptAES128(key, plaintext, 1, 100)
	if enc == nil {
		t.Fatal("encryptAES128 returned nil")
	}
	dec := decryptAES128(key, pp, enc, 1, 100)
	if dec == nil {
		t.Fatal("decryptAES128 returned nil")
	}
	if !bytesEqual(dec, plaintext) {
		t.Errorf("AES128 roundtrip failed: got %v, want %v", dec, plaintext)
	}
}
